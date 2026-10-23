package model

import (
	"math"
	"strings"
	"sync/atomic"
)

// ResultKind is the closed set of decisions a Processor can return.
type ResultKind uint8

const (
	ResultInvalid ResultKind = iota
	ResultContinue
	ResultRequestChange
	ResultResponseChange
	ResultRespond
	ResultStopPhase
	ResultReject
	ResultAbort
)

// Optional distinguishes an omitted patch field from an explicitly supplied
// empty value.
type Optional[T any] struct {
	Present bool
	Value   T
}

type BodyEditKind uint8

const (
	BodyKeep BodyEditKind = iota
	BodyReplace
)

// BodyEdit is constructor input. DoneResult copies its bytes into its own
// budgeted immutable storage; Replace with an empty slice differs from Keep.
type BodyEdit struct {
	Kind  BodyEditKind
	Bytes []byte
}

type RequestPatch struct {
	Method    Optional[string]
	URL       Optional[URLValue]
	Authority Optional[string]
	Headers   []HeaderEdit
	Body      BodyEdit
	Trailers  []HeaderEdit
}

type ResponsePatch struct {
	Status   Optional[int]
	Headers  []HeaderEdit
	Body     BodyEdit
	Trailers []HeaderEdit
}

type resultStorage struct {
	lease    *CopyLease
	released atomic.Bool
}

type syntheticPayload struct {
	status   int
	headers  HeaderBlock
	body     []byte
	trailers TrailerView
	storage  *resultStorage
	state    atomic.Uint32 // 0=standalone, 1=ownership transferred, 2=released
}

// SyntheticResponse has no reader, stream, file descriptor, or mutable getter.
// Its storage lease transfers to a DoneResult when passed to Respond.
type SyntheticResponse struct{ payload *syntheticPayload }

// DoneResult is immutable and closed: its zero value is ResultInvalid.
// Release the result after its payload has been committed or discarded.
type DoneResult struct{ payload *donePayload }

type donePayload struct {
	kind      ResultKind
	request   *RequestPatch
	response  *ResponsePatch
	synthetic *syntheticPayload
	code      string
	reason    string
	storage   *resultStorage
}

const maxDecisionText = 256

func newResultStorage(ledger *Ledger) (*resultStorage, error) {
	if ledger == nil {
		return nil, ErrInvalid
	}
	return &resultStorage{lease: NewCopyLease(ledger)}, nil
}

func (s *resultStorage) release() error {
	if s == nil || !s.released.CompareAndSwap(false, true) {
		return nil
	}
	return s.lease.Close()
}

func cloneResultString(lease *CopyLease, value string) (string, error) {
	n, err := copyCharge(int64(len(value)))
	if err != nil {
		return "", err
	}
	var out string
	err = lease.allocate(n, func() error {
		out = strings.Clone(value)
		return nil
	})
	return out, err
}

func cloneResultBytes(lease *CopyLease, value []byte) ([]byte, error) {
	n, err := copyCharge(int64(len(value)))
	if err != nil {
		return nil, err
	}
	var out []byte
	err = lease.allocate(n, func() error {
		out = append(make([]byte, 0, len(value)), value...)
		return nil
	})
	return out, err
}

func validateBodyEdit(edit BodyEdit, maxBodyBytes int64) error {
	if maxBodyBytes < 0 || edit.Kind > BodyReplace {
		return ErrInvalid
	}
	if edit.Kind == BodyKeep {
		if len(edit.Bytes) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if int64(len(edit.Bytes)) > maxBodyBytes {
		return ErrResourceLimit
	}
	return nil
}

func isManagedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "transfer-encoding", "connection", "proxy-connection", "keep-alive", "upgrade", "trailer", "host", "te":
		return true
	default:
		return strings.HasPrefix(name, ":")
	}
}

func cloneHeaderEdits(lease *CopyLease, edits []HeaderEdit) ([]HeaderEdit, error) {
	if len(edits) == 0 {
		return nil, nil
	}
	if len(edits) == 1 && edits[0].Kind == HeaderReplaceAll {
		if edits[0].Name != "" || len(edits[0].Values) != 0 {
			return nil, ErrInvalid
		}
	} else {
		for _, edit := range edits {
			if edit.Kind == HeaderReplaceAll {
				return nil, ErrInvalid
			}
		}
	}
	if int64(len(edits)) > (math.MaxInt64-128)/64 {
		return nil, ErrResourceLimit
	}
	var out []HeaderEdit
	err := lease.allocate(128+int64(len(edits))*64, func() error {
		out = make([]HeaderEdit, len(edits))
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i, edit := range edits {
		out[i].Kind = edit.Kind
		switch edit.Kind {
		case HeaderSet, HeaderAdd:
			if !validName(edit.Name) || isManagedHeader(edit.Name) || len(edit.Values) == 0 || edit.Block.lease != nil || len(edit.Block.fields) != 0 {
				return nil, ErrInvalid
			}
			var copyName string
			copyName, err = cloneResultString(lease, edit.Name)
			if err != nil {
				return nil, err
			}
			out[i].Name = copyName
			if int64(len(edit.Values)) > (math.MaxInt64-128)/32 {
				return nil, ErrResourceLimit
			}
			err = lease.allocate(128+int64(len(edit.Values))*32, func() error {
				out[i].Values = make([]string, len(edit.Values))
				return nil
			})
			if err != nil {
				return nil, err
			}
			for j, value := range edit.Values {
				if !validValue(value) {
					return nil, ErrInvalid
				}
				out[i].Values[j], err = cloneResultString(lease, value)
				if err != nil {
					return nil, err
				}
			}
		case HeaderRemove:
			if !validName(edit.Name) || isManagedHeader(edit.Name) || len(edit.Values) != 0 || edit.Block.lease != nil || len(edit.Block.fields) != 0 {
				return nil, ErrInvalid
			}
			out[i].Name, err = cloneResultString(lease, edit.Name)
			if err != nil {
				return nil, err
			}
		case HeaderReplaceAll:
			if len(edits) != 1 || edit.Name != "" || len(edit.Values) != 0 {
				return nil, ErrInvalid
			}
			for _, field := range edit.Block.fields {
				if isManagedHeader(field.Name) {
					return nil, ErrInvalid
				}
			}
			out[i].Block, err = edit.Block.Clone(lease)
			if err != nil {
				return nil, err
			}
		default:
			return nil, ErrInvalid
		}
	}
	return out, nil
}

func cloneBodyEdit(lease *CopyLease, edit BodyEdit, maxBodyBytes int64) (BodyEdit, error) {
	if err := validateBodyEdit(edit, maxBodyBytes); err != nil {
		return BodyEdit{}, err
	}
	out := BodyEdit{Kind: edit.Kind}
	if edit.Kind == BodyReplace {
		var err error
		out.Bytes, err = cloneResultBytes(lease, edit.Bytes)
		if err != nil {
			return BodyEdit{}, err
		}
	}
	return out, nil
}

func cloneRequestPatch(lease *CopyLease, patch RequestPatch, maxBodyBytes int64) (RequestPatch, error) {
	if err := validateBodyEdit(patch.Body, maxBodyBytes); err != nil {
		return RequestPatch{}, err
	}
	if patch.Method.Present && !validName(patch.Method.Value) || patch.URL.Present && patch.URL.Value.String() == "" || patch.Authority.Present && (!validValue(patch.Authority.Value) || patch.Authority.Value == "") {
		return RequestPatch{}, ErrInvalid
	}
	if len(patch.Trailers) != 0 && patch.Body.Kind != BodyReplace {
		return RequestPatch{}, ErrInvalid
	}
	if !patch.Method.Present && !patch.URL.Present && !patch.Authority.Present && len(patch.Headers) == 0 && patch.Body.Kind == BodyKeep && len(patch.Trailers) == 0 {
		return RequestPatch{}, ErrInvalid
	}
	var out RequestPatch
	var err error
	if patch.Method.Present {
		out.Method.Present = true
		out.Method.Value, err = cloneResultString(lease, patch.Method.Value)
		if err != nil {
			return RequestPatch{}, err
		}
	}
	if patch.URL.Present {
		out.URL.Present = true
		out.URL.Value, err = patch.URL.Value.clone(lease)
		if err != nil {
			return RequestPatch{}, err
		}
	}
	if patch.Authority.Present {
		out.Authority.Present = true
		out.Authority.Value, err = cloneResultString(lease, patch.Authority.Value)
		if err != nil {
			return RequestPatch{}, err
		}
	}
	out.Headers, err = cloneHeaderEdits(lease, patch.Headers)
	if err != nil {
		return RequestPatch{}, err
	}
	out.Body, err = cloneBodyEdit(lease, patch.Body, maxBodyBytes)
	if err != nil {
		return RequestPatch{}, err
	}
	out.Trailers, err = cloneHeaderEdits(lease, patch.Trailers)
	if err != nil {
		return RequestPatch{}, err
	}
	return out, nil
}

func cloneResponsePatch(lease *CopyLease, patch ResponsePatch, maxBodyBytes int64) (ResponsePatch, error) {
	if err := validateBodyEdit(patch.Body, maxBodyBytes); err != nil {
		return ResponsePatch{}, err
	}
	if patch.Status.Present && (patch.Status.Value < 200 || patch.Status.Value > 599) {
		return ResponsePatch{}, ErrInvalid
	}
	if patch.Status.Present && noBodyStatus(patch.Status.Value) && patch.Body.Kind == BodyReplace && len(patch.Body.Bytes) != 0 {
		return ResponsePatch{}, ErrInvalid
	}
	if len(patch.Trailers) != 0 && patch.Body.Kind != BodyReplace {
		return ResponsePatch{}, ErrInvalid
	}
	if !patch.Status.Present && len(patch.Headers) == 0 && patch.Body.Kind == BodyKeep && len(patch.Trailers) == 0 {
		return ResponsePatch{}, ErrInvalid
	}
	var out ResponsePatch
	var err error
	if patch.Status.Present {
		out.Status = patch.Status
	}
	out.Headers, err = cloneHeaderEdits(lease, patch.Headers)
	if err != nil {
		return ResponsePatch{}, err
	}
	out.Body, err = cloneBodyEdit(lease, patch.Body, maxBodyBytes)
	if err != nil {
		return ResponsePatch{}, err
	}
	out.Trailers, err = cloneHeaderEdits(lease, patch.Trailers)
	if err != nil {
		return ResponsePatch{}, err
	}
	return out, nil
}

func validateTrailerView(trailers TrailerView) bool {
	if trailers.availability == TrailerPending {
		return false
	}
	if trailers.availability == TrailerUnavailable && (trailers.declared.Len() != 0 || trailers.values.Len() != 0) {
		return false
	}
	for _, block := range []HeaderBlock{trailers.declared, trailers.values} {
		for _, field := range block.fields {
			if isManagedHeader(field.Name) {
				return false
			}
		}
	}
	return true
}

func Continue() DoneResult  { return DoneResult{payload: &donePayload{kind: ResultContinue}} }
func StopPhase() DoneResult { return DoneResult{payload: &donePayload{kind: ResultStopPhase}} }

// ChangeRequest copies patch into budgeted immutable storage. The caller must
// not mutate any patch slice concurrently with this constructor.
func ChangeRequest(patch RequestPatch, ledger *Ledger, maxBodyBytes int64) (DoneResult, error) {
	storage, err := newResultStorage(ledger)
	if err != nil {
		return DoneResult{}, err
	}
	copy, err := cloneRequestPatch(storage.lease, patch, maxBodyBytes)
	if err != nil {
		storage.release()
		return DoneResult{}, err
	}
	return DoneResult{payload: &donePayload{kind: ResultRequestChange, request: &copy, storage: storage}}, nil
}

// ChangeResponse copies patch into budgeted immutable storage. The caller must
// not mutate any patch slice concurrently with this constructor.
func ChangeResponse(patch ResponsePatch, ledger *Ledger, maxBodyBytes int64) (DoneResult, error) {
	storage, err := newResultStorage(ledger)
	if err != nil {
		return DoneResult{}, err
	}
	copy, err := cloneResponsePatch(storage.lease, patch, maxBodyBytes)
	if err != nil {
		storage.release()
		return DoneResult{}, err
	}
	return DoneResult{payload: &donePayload{kind: ResultResponseChange, response: &copy, storage: storage}}, nil
}

// NewSyntheticResponse copies a complete bounded body and immutable headers /
// trailers. The caller must not mutate body concurrently with this constructor.
func NewSyntheticResponse(status int, headers HeaderBlock, body []byte, trailers TrailerView, ledger *Ledger, maxBodyBytes int64) (SyntheticResponse, error) {
	if status < 200 || status > 599 || maxBodyBytes < 0 || !validateTrailerView(trailers) || noBodyStatus(status) && len(body) != 0 {
		return SyntheticResponse{}, ErrInvalid
	}
	if int64(len(body)) > maxBodyBytes {
		return SyntheticResponse{}, ErrResourceLimit
	}
	for _, field := range headers.fields {
		if isManagedHeader(field.Name) {
			return SyntheticResponse{}, ErrInvalid
		}
	}
	storage, err := newResultStorage(ledger)
	if err != nil {
		return SyntheticResponse{}, err
	}
	copyHeaders, err := headers.Clone(storage.lease)
	if err != nil {
		storage.release()
		return SyntheticResponse{}, err
	}
	copyBody, err := cloneResultBytes(storage.lease, body)
	if err != nil {
		storage.release()
		return SyntheticResponse{}, err
	}
	copyTrailers, err := trailers.clone(storage.lease)
	if err != nil {
		storage.release()
		return SyntheticResponse{}, err
	}
	return SyntheticResponse{payload: &syntheticPayload{status: status, headers: copyHeaders, body: copyBody, trailers: copyTrailers, storage: storage}}, nil
}

func noBodyStatus(status int) bool { return status == 204 || status == 205 || status == 304 }

func Respond(response SyntheticResponse) (DoneResult, error) {
	if response.payload == nil || response.payload.storage == nil || response.payload.storage.released.Load() {
		return DoneResult{}, ErrInvalid
	}
	if !response.payload.state.CompareAndSwap(0, 1) {
		if response.payload.state.Load() == 2 {
			return DoneResult{}, ErrReleased
		}
		return DoneResult{}, ErrInvalid
	}
	return DoneResult{payload: &donePayload{kind: ResultRespond, synthetic: response.payload, storage: response.payload.storage}}, nil
}

func Reject(code string, ledger *Ledger) (DoneResult, error) {
	if len(code) == 0 || len(code) > 64 || !validName(code) {
		return DoneResult{}, ErrInvalid
	}
	storage, err := newResultStorage(ledger)
	if err != nil {
		return DoneResult{}, err
	}
	copy, err := cloneResultString(storage.lease, code)
	if err != nil {
		storage.release()
		return DoneResult{}, err
	}
	return DoneResult{payload: &donePayload{kind: ResultReject, code: copy, storage: storage}}, nil
}

func Abort(reason string, ledger *Ledger) (DoneResult, error) {
	if len(reason) > maxDecisionText || !validValue(reason) {
		return DoneResult{}, ErrInvalid
	}
	storage, err := newResultStorage(ledger)
	if err != nil {
		return DoneResult{}, err
	}
	copy, err := cloneResultString(storage.lease, reason)
	if err != nil {
		storage.release()
		return DoneResult{}, err
	}
	return DoneResult{payload: &donePayload{kind: ResultAbort, reason: copy, storage: storage}}, nil
}

func (r DoneResult) Kind() ResultKind {
	if r.payload == nil {
		return ResultInvalid
	}
	return r.payload.kind
}

func (r DoneResult) Valid() bool {
	if r.payload == nil {
		return false
	}
	p := r.payload
	if p.storage != nil && p.storage.released.Load() {
		return false
	}
	switch p.kind {
	case ResultContinue, ResultStopPhase:
		return p.request == nil && p.response == nil && p.synthetic == nil && p.code == "" && p.reason == ""
	case ResultRequestChange:
		return p.request != nil && p.response == nil && p.synthetic == nil && p.code == "" && p.reason == ""
	case ResultResponseChange:
		return p.request == nil && p.response != nil && p.synthetic == nil && p.code == "" && p.reason == ""
	case ResultRespond:
		return p.request == nil && p.response == nil && p.synthetic != nil && p.code == "" && p.reason == ""
	case ResultReject:
		return p.request == nil && p.response == nil && p.synthetic == nil && p.code != "" && p.reason == ""
	case ResultAbort:
		return p.request == nil && p.response == nil && p.synthetic == nil && p.code == "" && len(p.reason) <= maxDecisionText
	default:
		return false
	}
}

// Same reports whether two DoneResult values refer to the same immutable
// payload. Completion uses it to avoid releasing a payload on duplicate Finish.
func (r DoneResult) Same(other DoneResult) bool { return r.payload == other.payload }

// AllocatedBytes reports the live bytes charged to this result's immutable
// payload lease. It is used for admission before Transaction.Commit.
func (r DoneResult) AllocatedBytes() int64 {
	if r.payload == nil || r.payload.storage == nil || r.payload.storage.lease == nil {
		return 0
	}
	return r.payload.storage.lease.ChargedBytes()
}

func (r DoneResult) ValidateForPhase(phase Phase) error {
	if !r.Valid() || phase != RequestPhase && phase != ResponsePhase {
		return ErrInvalid
	}
	switch r.Kind() {
	case ResultRequestChange, ResultRespond:
		if phase != RequestPhase {
			return ErrInvalid
		}
	case ResultResponseChange:
		if phase != ResponsePhase {
			return ErrInvalid
		}
	}
	return nil
}

// ValidateForInput adds request-specific semantics that cannot be checked by
// the phase-only validator. Framing and actual protocol output remain adapter work.
func (r DoneResult) ValidateForInput(input Input) error {
	phase := input.Key().Phase
	if err := r.ValidateForPhase(phase); err != nil {
		return err
	}
	if r.Kind() == ResultRespond {
		p := r.payload.synthetic
		if noBodyStatus(p.status) && len(p.body) != 0 || strings.EqualFold(input.Request().Method, "HEAD") && len(p.body) != 0 {
			return ErrInvalid
		}
	}
	if r.Kind() == ResultRequestChange && r.payload.request.URL.Present && r.payload.request.URL.Value.Profile() != input.Request().URL.Profile() {
		return ErrInvalid
	}
	if r.Kind() == ResultResponseChange {
		response, ok := input.Response()
		if !ok {
			return ErrInvalid
		}
		status := response.Status
		if r.payload.response.Status.Present {
			status = r.payload.response.Status.Value
		}
		if noBodyStatus(status) && r.payload.response.Body.Kind == BodyReplace && len(r.payload.response.Body.Bytes) != 0 {
			return ErrInvalid
		}
		if strings.EqualFold(input.Request().Method, "HEAD") && r.payload.response.Body.Kind == BodyReplace && len(r.payload.response.Body.Bytes) != 0 {
			return ErrInvalid
		}
	}
	return nil
}

func (r DoneResult) RequestPatch() (RequestPatch, bool, error) {
	if r.Kind() != ResultRequestChange || !r.Valid() {
		return RequestPatch{}, false, nil
	}
	copy, err := cloneRequestPatch(r.payload.storage.lease, *r.payload.request, math.MaxInt64)
	return copy, true, err
}

func (r DoneResult) ResponsePatch() (ResponsePatch, bool, error) {
	if r.Kind() != ResultResponseChange || !r.Valid() {
		return ResponsePatch{}, false, nil
	}
	copy, err := cloneResponsePatch(r.payload.storage.lease, *r.payload.response, math.MaxInt64)
	return copy, true, err
}

func (r DoneResult) SyntheticResponse() (SyntheticResponse, bool) {
	if r.Kind() != ResultRespond || !r.Valid() {
		return SyntheticResponse{}, false
	}
	return SyntheticResponse{payload: r.payload.synthetic}, true
}

func (r DoneResult) RejectCode() (string, bool, error) {
	if r.Kind() != ResultReject || !r.Valid() {
		return "", false, nil
	}
	copy, err := cloneResultString(r.payload.storage.lease, r.payload.code)
	return copy, true, err
}

func (r DoneResult) AbortReason() (string, bool, error) {
	if r.Kind() != ResultAbort || !r.Valid() {
		return "", false, nil
	}
	copy, err := cloneResultString(r.payload.storage.lease, r.payload.reason)
	return copy, true, err
}

// Release returns result-owned framework allocations to their ledger. The
// Pipeline owner must call this only after it has stopped borrowing the result.
func (r DoneResult) Release() error {
	if r.payload == nil {
		return nil
	}
	return r.payload.storage.release()
}

func (s SyntheticResponse) Status() int {
	if s.payload == nil {
		return 0
	}
	return s.payload.status
}

func (s SyntheticResponse) Headers() HeaderBlock {
	if s.payload == nil {
		return HeaderBlock{}
	}
	return s.payload.headers
}

func (s SyntheticResponse) BodyBytesCopy() ([]byte, error) {
	if s.payload == nil || s.payload.storage == nil || s.payload.storage.released.Load() {
		return nil, ErrReleased
	}
	return cloneResultBytes(s.payload.storage.lease, s.payload.body)
}

func (s SyntheticResponse) Trailers() TrailerView {
	if s.payload == nil {
		return TrailerView{}
	}
	return s.payload.trailers
}

func (s SyntheticResponse) Release() error {
	if s.payload == nil {
		return nil
	}
	if s.payload.state.CompareAndSwap(0, 2) {
		return s.payload.storage.release()
	}
	if s.payload.state.Load() == 2 {
		return nil
	}
	return ErrReleased
}
