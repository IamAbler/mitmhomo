package model

import (
	"context"
	"math"
	"strings"
	"sync"
)

// PipelinePhasePermit serializes a Transaction's Processor stages across
// independent Runner instances. Releasing the permit marks the phase consumed,
// including when execution failed, so a caller cannot accidentally replay
// entries against an exchange whose outcome is already uncertain.
type PipelinePhasePermit struct {
	tx    *Transaction
	phase Phase
	once  sync.Once
}

// AcquirePipelinePhase reserves the requested phase for one Runner. The bool
// result is true when a Response phase is intentionally skipped because the
// Request phase already committed a SyntheticResponse.
func (t *Transaction) AcquirePipelinePhase(ctx context.Context, phase Phase) (*PipelinePhasePermit, bool, error) {
	if t == nil || phase != RequestPhase && phase != ResponsePhase {
		return nil, false, ErrInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		cause := context.Cause(ctx)
		if cause == nil {
			cause = ctx.Err()
		}
		return nil, false, cause
	case <-t.ctx.Done():
		cause := context.Cause(t.ctx)
		if cause == nil {
			cause = t.ctx.Err()
		}
		return nil, false, cause
	case <-t.pipelineGate:
	}
	t.mu.Lock()
	if ctx.Err() != nil {
		err := context.Cause(ctx)
		if err == nil {
			err = ctx.Err()
		}
		t.mu.Unlock()
		t.pipelineGate <- struct{}{}
		return nil, false, err
	}
	if err := t.check(t.revision); err != nil {
		t.mu.Unlock()
		t.pipelineGate <- struct{}{}
		return nil, false, err
	}
	if phase == ResponsePhase && t.outcome == ExchangeSynthetic {
		t.mu.Unlock()
		t.pipelineGate <- struct{}{}
		return nil, true, nil
	}
	validOutcome := phase == RequestPhase && t.phase == RequestPhase && t.outcome == ExchangePending ||
		phase == ResponsePhase && t.phase == ResponsePhase && t.outcome == ExchangeUpstreamIssued
	if !validOutcome || t.pipelineDone[phase] || t.pipelineRunning != PhaseInvalid {
		t.mu.Unlock()
		t.pipelineGate <- struct{}{}
		return nil, false, ErrInvalid
	}
	t.pipelineRunning = phase
	t.mu.Unlock()
	return &PipelinePhasePermit{tx: t, phase: phase}, false, nil
}

// Release ends one serialized phase exactly once.
func (p *PipelinePhasePermit) Release() {
	if p == nil || p.tx == nil {
		return
	}
	p.once.Do(func() {
		p.tx.mu.Lock()
		if p.tx.pipelineRunning == p.phase {
			p.tx.pipelineRunning = PhaseInvalid
			p.tx.pipelineDone[p.phase] = true
		}
		p.tx.mu.Unlock()
		p.tx.pipelineGate <- struct{}{}
	})
}

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
	if key.TransactionID != t.id || key.Generation != t.generation || input.connection.ID != t.connection.ID || key.Phase != RequestPhase || t.phase != RequestPhase || key.Invocation == "" || key.Invocation != t.currentInvocation || t.outcome != ExchangePending || t.mainUpstreamIssued {
		return t.revision, ErrInvalid
	}
	if t.revision == Revision(math.MaxUint64) {
		return t.revision, ErrStaleRevision
	}
	t.mainUpstreamIssued = true
	t.outcome = ExchangeUpstreamIssued
	t.revision++
	t.currentInvocation = ""
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

// DecisionCopy returns budgeted copies of the policy code or abort reason for
// the terminal exchange outcome. The caller owns and must close it; reads
// remain available after Terminate and stop after Transaction.Close.
func (t *Transaction) DecisionCopy(to *CopyLease) (ExchangeOutcome, string, string, error) {
	if t == nil || to == nil {
		return ExchangePending, "", "", ErrInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == Closed {
		return t.outcome, "", "", ErrClosed
	}
	var code, reason string
	var err error
	if t.outcome == ExchangeRejected {
		code, err = cloneResultString(to, t.decisionCode)
	} else if t.outcome == ExchangeAborted {
		reason, err = cloneResultString(to, t.decisionReason)
	}
	return t.outcome, code, reason, err
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
	if key.TransactionID != t.id || key.Generation != t.generation || input.connection.ID != t.connection.ID || key.Phase != t.phase || key.Invocation == "" || key.Invocation != t.currentInvocation {
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
		t.currentInvocation = ""
		t.revision++
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
			err := t.replaceForCommit(input, broker, patch.Body.Bytes, func() {
				old := t.requestLease
				t.request, t.requestLease = head, lease
				t.revision++
				t.currentInvocation = ""
				old.Close()
			})
			if err != nil {
				lease.Close()
				return ResultInvalid, err
			}
			return ResultRequestChange, nil
		}
		old := t.requestLease
		t.request, t.requestLease = head, lease
		t.revision++
		t.currentInvocation = ""
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
			err := t.replaceForCommit(input, broker, patch.Body.Bytes, func() {
				old := t.responseLease
				t.response, t.responseLease = head, lease
				t.revision++
				t.currentInvocation = ""
				old.Close()
			})
			if err != nil {
				lease.Close()
				return ResultInvalid, err
			}
			return ResultResponseChange, nil
		}
		old := t.responseLease
		t.response, t.responseLease = head, lease
		t.revision++
		t.currentInvocation = ""
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
		t.currentInvocation = ""
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
		t.currentInvocation = ""
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
		t.currentInvocation = ""
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

// replaceForCommit preserves atomic Head/Body publication while the source's
// Read/Close and logical waiting happen outside the Transaction state lock.
// The caller holds mu on entry and again on return.
func (t *Transaction) replaceForCommit(input Input, broker *BodyBroker, data []byte, apply func()) error {
	committed := false
	t.mu.Unlock()
	err := broker.replace(t.ctx, data, func(publish func() error) error {
		t.mu.Lock()
		defer t.mu.Unlock()
		if err := t.check(input.key.Revision); err != nil {
			return err
		}
		if t.bodyLocked() != broker || t.currentInvocation != input.key.Invocation || t.phase != input.key.Phase {
			return ErrStaleRevision
		}
		if err := publish(); err != nil {
			return err
		}
		apply()
		committed = true
		return nil
	})
	t.mu.Lock()
	if committed {
		return nil
	}
	return err
}
