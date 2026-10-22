package model

import (
	"math"
	"strings"
)

// ClaimMainUpstream atomically reserves the Transaction's single main upstream
// request after its Request phase has completed. It records the transition in
// the owner state machine; it does not perform network I/O.
func (t *Transaction) ClaimMainUpstream(input Input) (Revision, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := input.key
	if err := t.check(key.Revision); err != nil {
		return t.revision, err
	}
	if key.TransactionID != t.id || key.Generation != t.generation || key.Phase != RequestPhase || t.phase != RequestPhase || key.Invocation == "" || t.outcome != ExchangePending || t.mainUpstreamIssued {
		return t.revision, ErrInvalid
	}
	if t.revision == Revision(math.MaxUint64) {
		return t.revision, ErrStaleRevision
	}
	t.mainUpstreamIssued = true
	t.outcome = ExchangeUpstreamIssued
	t.revision++
	return t.revision, nil
}

// TakeSynthetic transfers a committed SyntheticResponse from the Transaction
// owner to its eventual protocol/output owner. The caller must Release it after
// egress or disposal. A response can be taken only once.
func (t *Transaction) TakeSynthetic() (SyntheticResponse, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.outcome != ExchangeSynthetic || !t.hasSynthetic {
		return SyntheticResponse{}, false
	}
	response := t.synthetic
	t.synthetic = SyntheticResponse{}
	t.hasSynthetic = false
	return response, true
}

// Commit applies one DoneResult only when its detached Input still identifies
// the current Transaction revision. Identity checks, result validation,
// candidate preparation, optional Body replacement, and the final state swap
// all run under the Transaction owner lock. It is the only M4.7 entry point
// that applies Processor-produced changes.
func (t *Transaction) Commit(input Input, result DoneResult) (ResultKind, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := input.key
	if err := t.check(key.Revision); err != nil {
		return ResultInvalid, err
	}
	if key.TransactionID != t.id || key.Generation != t.generation || key.Phase != t.phase || key.Invocation == "" {
		return ResultInvalid, ErrInvalid
	}
	if key.Phase == RequestPhase && t.outcome != ExchangePending || key.Phase == ResponsePhase && t.outcome != ExchangeUpstreamIssued {
		return ResultInvalid, ErrClosed
	}
	if err := result.ValidateForInput(input); err != nil {
		return ResultInvalid, err
	}

	switch result.Kind() {
	case ResultContinue, ResultStopPhase:
		return result.Kind(), nil
	case ResultRequestChange:
		patch := *result.payload.request
		lease := NewCopyLease(t.ledger)
		head, err := makeRequestHead(lease, t.request, patch)
		if err != nil {
			lease.Close()
			return ResultInvalid, err
		}
		if patch.Body.Kind == BodyReplace {
			broker := t.requestBody.Broker()
			if broker == nil {
				lease.Close()
				return ResultInvalid, ErrBodyUnavailable
			}
			if err := broker.Replace(t.ctx, patch.Body.Bytes); err != nil {
				lease.Close()
				return ResultInvalid, err
			}
		}
		old := t.requestLease
		t.request, t.requestLease = head, lease
		t.revision++
		old.Close()
		return ResultRequestChange, nil
	case ResultResponseChange:
		patch := *result.payload.response
		lease := NewCopyLease(t.ledger)
		head, err := makeResponseHead(lease, t.response, patch)
		if err != nil {
			lease.Close()
			return ResultInvalid, err
		}
		if patch.Body.Kind == BodyReplace {
			broker := t.responseBody.Broker()
			if broker == nil {
				lease.Close()
				return ResultInvalid, ErrBodyUnavailable
			}
			if err := broker.Replace(t.ctx, patch.Body.Bytes); err != nil {
				lease.Close()
				return ResultInvalid, err
			}
		}
		old := t.responseLease
		t.response, t.responseLease = head, lease
		t.revision++
		old.Close()
		return ResultResponseChange, nil
	case ResultRespond:
		response, _ := result.SyntheticResponse()
		copy, err := response.cloneTo(t.ledger)
		if err != nil {
			return ResultInvalid, err
		}
		t.synthetic, t.hasSynthetic = copy, true
		t.outcome = ExchangeSynthetic
		t.revision++
		return ResultRespond, nil
	case ResultReject:
		code := result.payload.code
		lease := NewCopyLease(t.ledger)
		copy, err := cloneResultString(lease, code)
		if err != nil {
			lease.Close()
			return ResultInvalid, err
		}
		t.decisionLease = lease
		t.decisionCode = copy
		t.outcome = ExchangeRejected
		t.revision++
		return ResultReject, nil
	case ResultAbort:
		reason := result.payload.reason
		lease := NewCopyLease(t.ledger)
		copy, err := cloneResultString(lease, reason)
		if err != nil {
			lease.Close()
			return ResultInvalid, err
		}
		t.decisionLease = lease
		t.decisionReason = copy
		t.outcome = ExchangeAborted
		t.revision++
		return ResultAbort, nil
	default:
		return ResultInvalid, ErrInvalid
	}
}

func makeRequestHead(lease *CopyLease, old RequestHead, patch RequestPatch) (RequestHead, error) {
	method := old.Method
	if patch.Method.Present {
		method = patch.Method.Value
	}
	methodCopy, err := cloneResultString(lease, method)
	if err != nil {
		return RequestHead{}, err
	}
	urlValue := old.URL
	if patch.URL.Present {
		urlValue = patch.URL.Value
	}
	urlCopy, err := urlValue.clone(lease)
	if err != nil {
		return RequestHead{}, err
	}
	authority := old.Authority
	if patch.Authority.Present {
		authority = patch.Authority.Value
	}
	authorityCopy, err := cloneResultString(lease, authority)
	if err != nil {
		return RequestHead{}, err
	}
	headers, err := applyHeaderEdits(lease, old.Headers, patch.Headers, patch.Body.Kind == BodyReplace)
	if err != nil {
		return RequestHead{}, err
	}
	trailers, err := applyTrailerEdits(lease, old.Trailers, patch.Trailers, patch.Body.Kind == BodyReplace)
	if err != nil {
		return RequestHead{}, err
	}
	if !validName(methodCopy) || !validValue(authorityCopy) {
		return RequestHead{}, ErrInvalid
	}
	return RequestHead{Method: methodCopy, URL: urlCopy, Authority: authorityCopy, Headers: headers, Trailers: trailers}, nil
}

func makeResponseHead(lease *CopyLease, old ResponseHead, patch ResponsePatch) (ResponseHead, error) {
	status := old.Status
	if patch.Status.Present {
		status = patch.Status.Value
	}
	if status < 200 || status > 599 {
		return ResponseHead{}, ErrInvalid
	}
	headers, err := applyHeaderEdits(lease, old.Headers, patch.Headers, patch.Body.Kind == BodyReplace)
	if err != nil {
		return ResponseHead{}, err
	}
	trailers, err := applyTrailerEdits(lease, old.Trailers, patch.Trailers, patch.Body.Kind == BodyReplace)
	if err != nil {
		return ResponseHead{}, err
	}
	return ResponseHead{Status: status, Headers: headers, Trailers: trailers}, nil
}

func applyHeaderEdits(lease *CopyLease, base HeaderBlock, edits []HeaderEdit, replaceBody bool) (HeaderBlock, error) {
	fields := cloneHeaderFields(base.fields)
	if len(edits) == 1 && edits[0].Kind == HeaderReplaceAll {
		fields = cloneHeaderFields(edits[0].Block.fields)
	} else {
		for _, edit := range edits {
			index := headerFieldIndex(fields, edit.Name)
			switch edit.Kind {
			case HeaderSet:
				values := cloneStrings(edit.Values)
				if index < 0 {
					fields = append(fields, HeaderField{Name: edit.Name, Values: values})
				} else {
					fields[index].Values = values
				}
			case HeaderAdd:
				values := cloneStrings(edit.Values)
				if index < 0 {
					fields = append(fields, HeaderField{Name: edit.Name, Values: values})
				} else {
					fields[index].Values = append(fields[index].Values, values...)
				}
			case HeaderRemove:
				if index >= 0 {
					fields = append(fields[:index], fields[index+1:]...)
				}
			default:
				return HeaderBlock{}, ErrInvalid
			}
		}
	}
	if replaceBody {
		fields = removeBodyMetadata(fields)
	}
	return NewHeaderBlock(lease, fields)
}

func cloneHeaderFields(fields []HeaderField) []HeaderField {
	out := make([]HeaderField, len(fields))
	for i, field := range fields {
		out[i] = HeaderField{Name: field.Name, Values: cloneStrings(field.Values)}
	}
	return out
}

func cloneStrings(values []string) []string {
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func headerFieldIndex(fields []HeaderField, name string) int {
	for i := range fields {
		if strings.EqualFold(fields[i].Name, name) {
			return i
		}
	}
	return -1
}

func removeBodyMetadata(fields []HeaderField) []HeaderField {
	const invalidated = " content-length transfer-encoding trailer content-encoding content-md5 digest etag content-range "
	out := fields[:0]
	for _, field := range fields {
		name := " " + strings.ToLower(field.Name) + " "
		if !strings.Contains(invalidated, name) {
			out = append(out, field)
		}
	}
	return out
}

func applyTrailerEdits(lease *CopyLease, old TrailerView, edits []HeaderEdit, replaceBody bool) (TrailerView, error) {
	if !replaceBody {
		return old.clone(lease)
	}
	if len(edits) == 0 {
		return NewTrailerView(TrailerUnavailable, HeaderBlock{}, HeaderBlock{})
	}
	block, err := applyHeaderEdits(lease, HeaderBlock{}, edits, false)
	if err != nil {
		return TrailerView{}, err
	}
	return NewTrailerView(TrailerComplete, block, block)
}

func (s SyntheticResponse) cloneTo(ledger *Ledger) (SyntheticResponse, error) {
	storage, err := newResultStorage(ledger)
	if err != nil {
		return SyntheticResponse{}, err
	}
	headers, err := s.payload.headers.Clone(storage.lease)
	if err != nil {
		storage.release()
		return SyntheticResponse{}, err
	}
	body, err := cloneResultBytes(storage.lease, s.payload.body)
	if err != nil {
		storage.release()
		return SyntheticResponse{}, err
	}
	trailers, err := s.payload.trailers.clone(storage.lease)
	if err != nil {
		storage.release()
		return SyntheticResponse{}, err
	}
	return SyntheticResponse{payload: &syntheticPayload{status: s.payload.status, headers: headers, body: body, trailers: trailers, storage: storage}}, nil
}
