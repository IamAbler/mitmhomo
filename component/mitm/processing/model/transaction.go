package model

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"time"
)

type GenerationID uint64
type Revision uint64
type InvocationID string
type Phase uint8

const (
	PhaseInvalid Phase = iota
	RequestPhase
	ResponsePhase
)

type TransactionState uint8

const (
	Active TransactionState = iota
	Terminated
	Closed
)

type ResponseOrigin uint8

const (
	OriginUnknown ResponseOrigin = iota
	OriginUpstream
	OriginSynthetic
	OriginPolicy
)

type InvocationKey struct {
	TransactionID string
	Generation    GenerationID
	Phase         Phase
	Revision      Revision
	Invocation    InvocationID
}
type ProtocolInfo struct {
	Major, Minor int
	ALPN         string
	Known        bool
}
type ConnectionView struct {
	ID, StreamID, Source, Destination, SNI, Inbound string
	Downstream, Upstream                            ProtocolInfo
}
type RouteView struct {
	Known                     bool
	Target, LeaseID, Outbound string
}
type RequestHead struct {
	Method    string
	URL       URLValue
	Authority string // Distinct from URL.Host, not a duplicate header entry.
	Headers   HeaderBlock
	Trailers  TrailerView
}
type ResponseHead struct {
	Status   int
	Headers  HeaderBlock
	Trailers TrailerView
}

func (h RequestHead) clone(to *CopyLease) (RequestHead, error) {
	if !validName(h.Method) || h.URL.String() == "" || !validValue(h.Authority) {
		return RequestHead{}, ErrInvalid
	}
	var out RequestHead
	n, err := copyCharge(int64(len(h.Method)) + int64(len(h.Authority)))
	if err != nil {
		return out, err
	}
	err = to.allocate(n, func() error {
		out.Method = strings.Clone(h.Method)
		out.Authority = strings.Clone(h.Authority)
		return nil
	})
	if err != nil {
		return out, err
	}
	out.URL, err = h.URL.clone(to)
	if err != nil {
		return out, err
	}
	out.Headers, err = h.Headers.Clone(to)
	if err != nil {
		return out, err
	}
	out.Trailers, err = h.Trailers.clone(to)
	return out, err
}
func (h ResponseHead) clone(to *CopyLease) (ResponseHead, error) {
	if h.Status < 200 || h.Status > 599 {
		return ResponseHead{}, ErrInvalid
	}
	out := ResponseHead{Status: h.Status}
	var err error
	out.Headers, err = h.Headers.Clone(to)
	if err != nil {
		return out, err
	}
	out.Trailers, err = h.Trailers.clone(to)
	return out, err
}

type TransactionOptions struct {
	ID              string
	Generation      GenerationID
	Connection      ConnectionView
	Route           RouteView
	OriginalIngress RequestHead
	Request         RequestHead // Entry after any protocol/internal hook processing.
	RequestBody     BodySlot
	Ledger          *Ledger
}

// Transaction is an owner API, not a processor input. Mutations require the
// current revision. Its lock also permits cancellation/Close racing snapshots.
// Successful construction/EnterResponse transfers the supplied BodySlot to it;
// the caller must not concurrently operate the same broker via another alias.
type Transaction struct {
	mu                                        sync.Mutex
	ctx                                       context.Context
	cancel                                    context.CancelCauseFunc
	ledger                                    *Ledger
	id                                        string
	generation                                GenerationID
	connection                                ConnectionView
	route                                     RouteView
	phase                                     Phase
	revision                                  Revision
	state                                     TransactionState
	origin                                    ResponseOrigin
	ingress, phaseRequest, request            RequestHead
	originalResponse, phaseResponse, response ResponseHead
	ingressLease                              *CopyLease
	entryLease                                *CopyLease
	requestLease                              *CopyLease
	originalResponseLease                     *CopyLease
	responseLease                             *CopyLease
	requestBody, responseBody                 BodySlot
	closeErr                                  error
}

func NewTransaction(parent context.Context, options TransactionOptions) (*Transaction, error) {
	if options.ID == "" || options.Connection.ID == "" || options.Ledger == nil {
		return nil, ErrInvalid
	}
	if parent == nil {
		parent = context.Background()
	}
	if parent.Err() != nil {
		return nil, context.Cause(parent)
	}
	ctx, cancel := context.WithCancelCause(parent)
	t := &Transaction{ctx: ctx, cancel: cancel, ledger: options.Ledger, generation: options.Generation, phase: RequestPhase, revision: 1, requestBody: options.RequestBody}
	t.ingressLease = NewCopyLease(t.ledger)
	t.entryLease = NewCopyLease(t.ledger)
	t.requestLease = NewCopyLease(t.ledger)
	var err error
	success := false
	defer func() {
		if !success {
			t.ingressLease.Close()
			t.entryLease.Close()
			t.requestLease.Close()
			cancel(context.Canceled)
		}
	}()
	t.id, t.connection, t.route, err = cloneMetadata(t.ingressLease, options.ID, options.Connection, options.Route)
	if err != nil {
		return nil, err
	}
	t.ingress, err = options.OriginalIngress.clone(t.ingressLease)
	if err != nil {
		return nil, err
	}
	t.phaseRequest, err = options.Request.clone(t.entryLease)
	if err != nil {
		return nil, err
	}
	t.request, err = options.Request.clone(t.requestLease)
	if err != nil {
		return nil, err
	}
	success = true
	return t, nil
}

func cloneMetadata(to *CopyLease, id string, connection ConnectionView, route RouteView) (string, ConnectionView, RouteView, error) {
	fields := []string{id, connection.ID, connection.StreamID, connection.Source, connection.Destination, connection.SNI, connection.Inbound, connection.Downstream.ALPN, connection.Upstream.ALPN, route.Target, route.LeaseID, route.Outbound}
	n := int64(256)
	for _, s := range fields {
		if int64(len(s)) > math.MaxInt64-n {
			return "", ConnectionView{}, RouteView{}, ErrResourceLimit
		}
		n += int64(len(s))
	}
	var copiedID string
	err := to.allocate(n, func() error {
		copiedID = strings.Clone(id)
		connection.ID = strings.Clone(connection.ID)
		connection.StreamID = strings.Clone(connection.StreamID)
		connection.Source = strings.Clone(connection.Source)
		connection.Destination = strings.Clone(connection.Destination)
		connection.SNI = strings.Clone(connection.SNI)
		connection.Inbound = strings.Clone(connection.Inbound)
		connection.Downstream.ALPN = strings.Clone(connection.Downstream.ALPN)
		connection.Upstream.ALPN = strings.Clone(connection.Upstream.ALPN)
		route.Target = strings.Clone(route.Target)
		route.LeaseID = strings.Clone(route.LeaseID)
		route.Outbound = strings.Clone(route.Outbound)
		return nil
	})
	return copiedID, connection, route, err
}

func (t *Transaction) Context() context.Context    { return t.ctx }
func (t *Transaction) Deadline() (time.Time, bool) { return t.ctx.Deadline() }
func (t *Transaction) CancellationCause() error    { return context.Cause(t.ctx) }
func (t *Transaction) Revision() Revision          { t.mu.Lock(); defer t.mu.Unlock(); return t.revision }
func (t *Transaction) Phase() Phase                { t.mu.Lock(); defer t.mu.Unlock(); return t.phase }
func (t *Transaction) State() TransactionState     { t.mu.Lock(); defer t.mu.Unlock(); return t.state }
func (t *Transaction) Ledger() *Ledger             { return t.ledger } // Owner-only accounting.

func (t *Transaction) check(expected Revision) error {
	if t.state != Active {
		return ErrClosed
	}
	if t.ctx.Err() != nil {
		return context.Cause(t.ctx)
	}
	if t.revision != expected || t.revision == Revision(math.MaxUint64) {
		return ErrStaleRevision
	}
	return nil
}

func (t *Transaction) UpdateRequest(expected Revision, head RequestHead) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.check(expected); err != nil {
		return err
	}
	if t.phase != RequestPhase {
		return ErrInvalid
	}
	lease := NewCopyLease(t.ledger)
	copy, err := head.clone(lease)
	if err != nil {
		lease.Close()
		return err
	}
	old := t.requestLease
	t.request, t.requestLease = copy, lease
	t.revision++
	old.Close()
	return nil
}

func (t *Transaction) EnterResponse(expected Revision, original, entry ResponseHead, body BodySlot, origin ResponseOrigin) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.check(expected); err != nil {
		return err
	}
	if t.phase != RequestPhase || origin < OriginUpstream || origin > OriginPolicy {
		return ErrInvalid
	}
	originalLease, entryLease, workLease := NewCopyLease(t.ledger), NewCopyLease(t.ledger), NewCopyLease(t.ledger)
	success := false
	defer func() {
		if !success {
			originalLease.Close()
			entryLease.Close()
			workLease.Close()
		}
	}()
	orig, err := original.clone(originalLease)
	if err != nil {
		return err
	}
	phaseRequest, err := t.request.clone(entryLease)
	if err != nil {
		return err
	}
	phaseResponse, err := entry.clone(entryLease)
	if err != nil {
		return err
	}
	work, err := entry.clone(workLease)
	if err != nil {
		return err
	}
	t.entryLease.Close()
	t.originalResponseLease, t.entryLease, t.responseLease = originalLease, entryLease, workLease
	t.originalResponse, t.phaseResponse, t.response = orig, phaseResponse, work
	t.phaseRequest = phaseRequest
	t.responseBody = body
	t.origin = origin
	t.phase = ResponsePhase
	t.revision++
	success = true
	return nil
}
func (t *Transaction) UpdateResponse(expected Revision, head ResponseHead) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.check(expected); err != nil {
		return err
	}
	if t.phase != ResponsePhase {
		return ErrInvalid
	}
	lease := NewCopyLease(t.ledger)
	copy, err := head.clone(lease)
	if err != nil {
		lease.Close()
		return err
	}
	old := t.responseLease
	t.response, t.responseLease = copy, lease
	t.revision++
	old.Close()
	return nil
}
func (t *Transaction) bodyLocked() *BodyBroker {
	if t.phase == ResponsePhase {
		return t.responseBody.broker
	}
	return t.requestBody.broker
}
func (t *Transaction) PrepareBody(need BodyNeed, limit int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.check(t.revision); err != nil {
		return err
	}
	b := t.bodyLocked()
	if b == nil {
		if need == None {
			return nil
		}
		return ErrBodyUnavailable
	}
	return b.Prepare(t.ctx, need, limit)
}
func (t *Transaction) ReplaceBody(expected Revision, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.check(expected); err != nil {
		return err
	}
	b := t.bodyLocked()
	if b == nil {
		return ErrBodyUnavailable
	}
	if err := b.Replace(t.ctx, data); err != nil {
		return err
	}
	t.revision++
	return nil
}
func (t *Transaction) TakeBody() (io.ReadCloser, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.check(t.revision); err != nil {
		return nil, err
	}
	b := t.bodyLocked()
	if b == nil {
		return nil, ErrBodyUnavailable
	}
	return b.TakeStream(t.ctx)
}

func (t *Transaction) Terminate(cause error) {
	if cause == nil {
		cause = context.Canceled
	}
	t.cancel(cause) // Must precede locking: a cooperative in-flight read may wait.
	t.mu.Lock()
	if t.state == Active {
		t.state = Terminated
	}
	t.mu.Unlock()
}
func (t *Transaction) Close() error {
	if t == nil {
		return nil
	}
	t.cancel(context.Canceled)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != Closed {
		t.state = Closed
		t.closeErr = errors.Join(t.requestBody.Close(), t.responseBody.Close())
		for _, lease := range []*CopyLease{t.ingressLease, t.entryLease, t.requestLease, t.originalResponseLease, t.responseLease} {
			lease.Close()
		}
	}
	return t.closeErr
}

// Input has only detached values and private immutable allocations. Its copy
// lease is returned separately to the owner, never through this input API.
type Input struct {
	key                                       InvocationKey
	connection                                ConnectionView
	route                                     RouteView
	origin                                    ResponseOrigin
	ingress, phaseRequest, request            RequestHead
	originalResponse, phaseResponse, response ResponseHead
	body                                      BodyView
}

func (i Input) Key() InvocationKey                  { return i.key }
func (i Input) Connection() ConnectionView          { return i.connection }
func (i Input) Route() RouteView                    { return i.route }
func (i Input) Origin() ResponseOrigin              { return i.origin }
func (i Input) OriginalIngress() RequestHead        { return i.ingress }
func (i Input) OriginalPhaseRequest() RequestHead   { return i.phaseRequest }
func (i Input) OriginalResponse() ResponseHead      { return i.originalResponse }
func (i Input) OriginalPhaseResponse() ResponseHead { return i.phaseResponse }
func (i Input) Request() RequestHead                { return i.request }
func (i Input) Response() (ResponseHead, bool)      { return i.response, i.key.Phase == ResponsePhase }
func (i Input) Body() BodyView                      { return i.body }

func (t *Transaction) Snapshot(invocation InvocationID) (Input, *CopyLease, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.check(t.revision); err != nil {
		return Input{}, nil, err
	}
	if invocation == "" {
		return Input{}, nil, ErrInvalid
	}
	lease := NewCopyLease(t.ledger)
	failed := true
	defer func() {
		if failed {
			lease.Close()
		}
	}()
	var out Input
	id, connection, route, err := cloneMetadata(lease, t.id, t.connection, t.route)
	if err != nil {
		return Input{}, nil, err
	}
	if err := lease.allocate(int64(len(invocation))+128, func() error { out.key.Invocation = InvocationID(strings.Clone(string(invocation))); return nil }); err != nil {
		return Input{}, nil, err
	}
	out.key.TransactionID = id
	out.key.Generation = t.generation
	out.key.Phase = t.phase
	out.key.Revision = t.revision
	out.connection, out.route, out.origin = connection, route, t.origin
	out.ingress, err = t.ingress.clone(lease)
	if err != nil {
		return Input{}, nil, err
	}
	out.phaseRequest, err = t.phaseRequest.clone(lease)
	if err != nil {
		return Input{}, nil, err
	}
	out.request, err = t.request.clone(lease)
	if err != nil {
		return Input{}, nil, err
	}
	if t.phase == ResponsePhase {
		out.originalResponse, err = t.originalResponse.clone(lease)
		if err != nil {
			return Input{}, nil, err
		}
		out.phaseResponse, err = t.phaseResponse.clone(lease)
		if err != nil {
			return Input{}, nil, err
		}
		out.response, err = t.response.clone(lease)
		if err != nil {
			return Input{}, nil, err
		}
	}
	if b := t.bodyLocked(); b != nil {
		out.body, err = b.Snapshot(lease)
		if err != nil {
			return Input{}, nil, err
		}
	}
	failed = false
	return out, lease, nil
}
