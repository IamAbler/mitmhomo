package mitm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

var processingHTTPSequence atomic.Uint64

var (
	errProcessingRejected = errors.New("HTTP processing rejected")
	errProcessingAborted  = errors.New("HTTP processing aborted")
)

type responseHookFramingKey struct{}

type responseHookFraming struct {
	mu      sync.Mutex
	changed bool
	values  []string
}

func (f *responseHookFraming) record(values []string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.changed = true
	f.values = append([]string(nil), values...)
	f.mu.Unlock()
}

func (f *responseHookFraming) validate(tx *model.Transaction) error {
	if f == nil || tx == nil {
		return nil
	}
	f.mu.Lock()
	changed := f.changed
	values := append([]string(nil), f.values...)
	f.mu.Unlock()
	if !changed || len(values) == 0 {
		return nil
	}
	info := tx.BodyInfo(model.ResponsePhase)
	if info.State == model.Replaced {
		// A later processor replaced the representation and owns the final
		// framing length.
		return nil
	}
	input, lease, err := tx.Snapshot("response-hook-framing")
	if err != nil {
		return err
	}
	defer lease.Close()
	response, ok := input.Response()
	if !ok || responseForbidsBody(response.Status) || input.Request().Method == http.MethodHead {
		return nil
	}
	length, present, err := parseResponseContentLength(http.Header{"Content-Length": values})
	if err != nil {
		return model.NewProcessingError(model.ProcessingErrorProtocol, model.ProcessingOriginProtocol, model.ResponsePhase, "internal-response-hook", "", err)
	}
	if present && info.Length >= 0 && length != info.Length {
		return model.NewProcessingError(model.ProcessingErrorProtocol, model.ProcessingOriginProtocol, model.ResponsePhase, "internal-response-hook", "", fmt.Errorf("response hook Content-Length %d does not match body length %d", length, info.Length))
	}
	return nil
}

func processingConnectionID() string {
	return fmt.Sprintf("mitm-connection-%d", processingHTTPSequence.Add(1))
}

func processingStreamID() string {
	return fmt.Sprintf("stream-%d", processingHTTPSequence.Add(1))
}

func makeHTTPHeaders(lease *model.CopyLease, headers http.Header) (model.HeaderBlock, error) {
	return model.NewHeaderBlock(lease, ordinaryHeaderFields(headers))
}

func makeHTTPTrailers(lease *model.CopyLease, trailers http.Header, complete bool) (model.TrailerView, error) {
	declaredFields := make([]model.HeaderField, 0, len(trailers))
	valueFields := make([]model.HeaderField, 0, len(trailers))
	for _, name := range sortedHeaderNames(trailers) {
		if processingHopHeader(name) || strings.EqualFold(name, "Host") {
			continue
		}
		declaredFields = append(declaredFields, model.HeaderField{Name: name})
		if complete {
			values := append([]string(nil), trailers.Values(name)...)
			if len(values) != 0 {
				valueFields = append(valueFields, model.HeaderField{Name: name, Values: values})
			}
		}
	}
	declared, err := model.NewHeaderBlock(lease, declaredFields)
	if err != nil {
		return model.TrailerView{}, err
	}
	values, err := model.NewHeaderBlock(lease, valueFields)
	if err != nil {
		return model.TrailerView{}, err
	}
	state := model.TrailerUnavailable
	if len(declaredFields) != 0 {
		state = model.TrailerPending
		if complete {
			state = model.TrailerComplete
		}
	}
	return model.NewTrailerView(state, declared, values)
}

func makeRequestHead(lease *model.CopyLease, request *http.Request, target *url.URL, trailerSource http.Header, trailersComplete bool) (model.RequestHead, error) {
	if request == nil || target == nil {
		return model.RequestHead{}, model.ErrInvalid
	}
	parsed, err := model.ParseURL(lease, target.String(), model.MITMHTTPS)
	if err != nil {
		return model.RequestHead{}, err
	}
	headers, err := makeHTTPHeaders(lease, request.Header)
	if err != nil {
		return model.RequestHead{}, err
	}
	trailers, err := makeHTTPTrailers(lease, trailerSource, trailersComplete)
	if err != nil {
		return model.RequestHead{}, err
	}
	authority := request.Host
	if authority == "" {
		authority = target.Host
	}
	return model.RequestHead{Method: request.Method, URL: parsed, Authority: authority, Headers: headers, Trailers: trailers}, nil
}

func makeResponseHead(lease *model.CopyLease, response *http.Response, trailersComplete bool) (model.ResponseHead, error) {
	if response == nil {
		return model.ResponseHead{}, model.ErrInvalid
	}
	headers, err := makeHTTPHeaders(lease, response.Header)
	if err != nil {
		return model.ResponseHead{}, err
	}
	trailers, err := makeHTTPTrailers(lease, response.Trailer, trailersComplete)
	if err != nil {
		return model.ResponseHead{}, err
	}
	return model.ResponseHead{Status: response.StatusCode, Headers: headers, Trailers: trailers}, nil
}

func newRequestTransaction(
	ctx context.Context,
	request, ingress *http.Request,
	requestTarget, ingressTarget *url.URL,
	requestBodyStillServerOwned bool,
	requestTrailerSource http.Header,
	connectionID string,
	processing *generation.BoundRunner,
	stream *generation.Lease,
) (*model.Transaction, error) {
	if request == nil || ingress == nil || processing == nil || stream == nil {
		return nil, model.ErrInvalid
	}
	ledger, err := model.NewLedger(-1, nil)
	if err != nil {
		return nil, err
	}
	copyLease := model.NewCopyLease(ledger)
	defer copyLease.Close()
	originalHead, err := makeRequestHead(copyLease, ingress, ingressTarget, ingress.Trailer, false)
	if err != nil {
		return nil, err
	}
	entryHead, err := makeRequestHead(copyLease, request, requestTarget, request.Trailer, false)
	if err != nil {
		return nil, err
	}
	body := request.Body
	owner := model.FrameworkOwned
	var interrupt func()
	if requestBodyStillServerOwned {
		if source, ok := InboundBodySourceFromContext(request.Context()); ok && source.Reader != nil {
			body = source.Reader
			owner = model.ServerOwned
			interrupt = source.Interrupt
		}
	}
	trailerSnapshotSource := request.Trailer
	if owner == model.ServerOwned && requestTrailerSource != nil {
		trailerSnapshotSource = requestTrailerSource
	}
	if body == nil {
		body = http.NoBody
	}
	declaredLength := request.ContentLength
	if declaredLength < 0 {
		declaredLength = -1
	}
	broker, err := model.NewBodyBroker(ctx, model.BodySource{
		Reader: body, Owner: owner, DeclaredLength: declaredLength, Interrupt: interrupt,
		SnapshotTrailers: func(lease *model.CopyLease) (model.TrailerView, error) {
			return makeHTTPTrailers(lease, trailerSnapshotSource, true)
		},
		AcquireExecution: func() (io.Closer, error) { return stream.Execution() },
	}, ledger)
	if err != nil {
		return nil, err
	}
	bodySlot := model.NewBodySlot(broker)
	connection := model.ConnectionView{
		ID: connectionID, StreamID: processingStreamID(), Source: request.RemoteAddr,
		Downstream: model.ProtocolInfo{Major: request.ProtoMajor, Minor: request.ProtoMinor, Known: true},
	}
	if request.TLS != nil {
		connection.Downstream.ALPN = request.TLS.NegotiatedProtocol
	}
	tx, err := model.NewTransaction(ctx, model.TransactionOptions{
		ID: connection.StreamID, Generation: processing.GenerationID(), Connection: connection,
		OriginalIngress: originalHead, Request: entryHead, RequestBody: bodySlot, Ledger: ledger,
	})
	if err != nil {
		_ = bodySlot.Close()
		return nil, err
	}
	return tx, nil
}

func enterUpstreamResponse(tx *model.Transaction, response *http.Response, stream *generation.Lease) error {
	if tx == nil || response == nil || stream == nil {
		return model.ErrInvalid
	}
	ledger := tx.Ledger()
	copyLease := model.NewCopyLease(ledger)
	defer copyLease.Close()
	head, err := makeResponseHead(copyLease, response, false)
	if err != nil {
		return err
	}
	body := response.Body
	if body == nil {
		body = http.NoBody
	}
	declaredLength := response.ContentLength
	if responseForbidsBody(response.StatusCode) || response.Request != nil && response.Request.Method == http.MethodHead || body == http.NoBody {
		declaredLength = 0
	} else if declaredLength < 0 {
		declaredLength = -1
	}
	broker, err := model.NewBodyBroker(tx.Context(), model.BodySource{
		Reader: body, Owner: model.TransportOwned, DeclaredLength: declaredLength,
		Interrupt: func() { _ = body.Close() },
		SnapshotTrailers: func(lease *model.CopyLease) (model.TrailerView, error) {
			return makeHTTPTrailers(lease, response.Trailer, true)
		},
		AcquireExecution: func() (io.Closer, error) { return stream.Execution() },
	}, ledger)
	if err != nil {
		return err
	}
	bodySlot := model.NewBodySlot(broker)
	if err := tx.EnterResponse(tx.Revision(), head, head, bodySlot, model.OriginUpstream); err != nil {
		_ = bodySlot.Close()
		return err
	}
	return nil
}

func applyRequestTransaction(request *http.Request, tx *model.Transaction) (model.BodyInfo, error) {
	if request == nil || tx == nil {
		return model.BodyInfo{}, model.ErrInvalid
	}
	head, lease, err := tx.Snapshot("http-egress")
	if err != nil {
		return model.BodyInfo{}, err
	}
	defer lease.Close()
	requestHead := head.Request()
	target, err := url.Parse(requestHead.URL.String())
	if err != nil || target == nil {
		return model.BodyInfo{}, model.ErrInvalid
	}
	request.URL = target
	request.Host = requestHead.Authority
	request.Method = requestHead.Method
	request.RequestURI = ""
	headers, err := modelHeaderToHTTP(requestHead.Headers)
	if err != nil {
		return model.BodyInfo{}, err
	}
	request.Header = headers
	request.TransferEncoding = nil
	request.Trailer = make(http.Header)
	if declared, err := requestHead.Trailers.Declared().Entries(); err == nil {
		for _, field := range declared {
			request.Trailer[field.Name] = nil
		}
	}
	if values, err := requestHead.Trailers.Values(); err == nil {
		if entries, entriesErr := values.Entries(); entriesErr == nil {
			for _, field := range entries {
				request.Trailer[field.Name] = append([]string(nil), field.Values...)
			}
		}
	}
	info := tx.BodyInfo(model.RequestPhase)
	requestBody, err := tx.TakeBody()
	if err != nil {
		return info, err
	}
	if info.State == model.Replaced || info.State == model.FullBufferedState {
		request.ContentLength = info.Length
	}
	request.Body = requestBody
	if request.ContentLength == 0 {
		request.Body = http.NoBody
		_ = requestBody.Close()
	} else if request.ContentLength > 0 {
		request.Body = &requestDeclaredLengthBody{ReadCloser: requestBody, remaining: request.ContentLength}
	}
	if info.State == model.Replaced {
		request.Trailer = nil
		for _, name := range []string{"Content-Length", "Transfer-Encoding", "Trailer"} {
			request.Header.Del(name)
		}
	} else if request.ContentLength < 0 {
		request.ContentLength = -1
	}
	return info, nil
}

// requestDeclaredLengthBody makes the inbound BodyBroker observe EOF after a
// Transport has copied exactly Content-Length bytes. net/http may close a
// known-length request body without issuing that final Read; the extra read is
// needed to distinguish a completed upload from one that still needs server
// disposal.
type requestDeclaredLengthBody struct {
	io.ReadCloser
	remaining int64
	verified  bool
}

func (b *requestDeclaredLengthBody) Read(p []byte) (int, error) {
	if b == nil || b.ReadCloser == nil {
		return 0, model.ErrInvalid
	}
	if b.verified {
		return 0, io.EOF
	}
	if b.remaining == 0 {
		var probe [1]byte
		n, err := b.ReadCloser.Read(probe[:])
		if n != 0 {
			return 0, io.ErrUnexpectedEOF
		}
		if err == io.EOF {
			b.verified = true
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if err == nil && b.remaining == 0 {
		var probe [1]byte
		probeN, probeErr := b.ReadCloser.Read(probe[:])
		if probeN != 0 {
			return n, io.ErrUnexpectedEOF
		}
		if probeErr == io.EOF {
			b.verified = true
			return n, io.EOF
		}
		if probeErr != nil {
			return n, probeErr
		}
	}
	return n, err
}

func applyResponseTransaction(response *http.Response, tx *model.Transaction, downstreamMethod string) error {
	if response == nil || tx == nil {
		return model.ErrInvalid
	}
	input, lease, err := tx.Snapshot("http-response-egress")
	if err != nil {
		return err
	}
	defer lease.Close()
	head, ok := input.Response()
	if !ok {
		return model.ErrInvalid
	}
	finalFields, err := modelHeaderToHTTP(head.Headers)
	if err != nil {
		return err
	}
	info := tx.BodyInfo(model.ResponsePhase)
	originalStatus := input.OriginalResponse().Status
	representationLength := response.ContentLength
	upstreamHead := input.Request().Method == http.MethodHead
	originalBodyUnavailable := upstreamHead || responseForbidsBody(originalStatus)
	if info.State == model.Replaced || info.State == model.FullBufferedState && response.ContentLength < 0 {
		representationLength = info.Length
	}
	header := response.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}
	for name := range header {
		if !strings.EqualFold(name, "Content-Length") && !strings.EqualFold(name, "Trailer") {
			header.Del(name)
		}
	}
	if info.State == model.Replaced {
		clearReplacedRepresentationHeaders(header)
		response.Trailer = nil
		header.Del("Trailer")
	}
	for name, values := range finalFields {
		header[name] = append([]string(nil), values...)
	}
	response.StatusCode = head.Status
	response.Status = responseStatus(head.Status)
	response.Header = header
	response.TransferEncoding = nil
	removeResponseHopByHopHeaders(header, response.Trailer)

	body, err := tx.TakeBody()
	if err != nil {
		return err
	}
	suppressBody := downstreamMethod == http.MethodHead || responseForbidsBody(head.Status)
	bodyUnavailable := originalBodyUnavailable && info.State != model.Replaced
	if suppressBody || bodyUnavailable {
		_ = body.Close()
		response.Body = http.NoBody
	} else {
		response.Body = body
	}
	if info.State == model.Replaced {
		response.ContentLength = representationLength
		if head.Status == http.StatusNoContent {
			header.Del("Content-Length")
		} else if head.Status == http.StatusResetContent {
			header.Set("Content-Length", "0")
			response.ContentLength = 0
		} else if head.Status == http.StatusNotModified {
			// The replacement is a representation change, but 304 has no
			// payload. Omitting Content-Length also avoids advertising bytes
			// that the HTTP/2 writer must never send on this stream.
			header.Del("Content-Length")
			response.ContentLength = -1
		} else {
			header.Set("Content-Length", fmt.Sprint(representationLength))
		}
	} else if suppressBody {
		response.ContentLength = representationLength
		if (upstreamHead || responseForbidsBody(originalStatus)) && head.Status == http.StatusNotModified && info.State != model.Replaced {
			header.Del("Content-Length")
			response.ContentLength = -1
		}
	}
	if bodyUnavailable && !suppressBody {
		// The original exchange returned no payload (HEAD, 204, 205 or 304),
		// then a later processor selected a content-bearing status. Preserve
		// the existing adapter behavior: send an empty body with length zero.
		clearReplacedRepresentationHeaders(header)
		header.Set("Content-Length", "0")
		response.ContentLength = 0
	}
	if suppressBody && response.Trailer != nil {
		response.Trailer = nil
		header.Del("Trailer")
	}
	return normalizeResponseFraming(response, header, head.Status, downstreamMethod, suppressBody)
}

type commitTrackingWriter struct {
	http.ResponseWriter
	committed bool
}

func (w *commitTrackingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *commitTrackingWriter) WriteHeader(status int) {
	if w.committed {
		return
	}
	if status >= http.StatusOK || status == http.StatusSwitchingProtocols {
		w.committed = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *commitTrackingWriter) Write(body []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *commitTrackingWriter) Flush() { _ = w.FlushError() }

func (w *commitTrackingWriter) FlushError() error {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *commitTrackingWriter) Committed() bool { return w != nil && w.committed }

func writeProcessingFailure(w *commitTrackingWriter, request *http.Request, err error, phase model.Phase) {
	if err == nil || request != nil && request.Context().Err() != nil && !errors.Is(context.Cause(request.Context()), context.DeadlineExceeded) {
		return
	}
	if w.Committed() {
		panic(http.ErrAbortHandler)
	}
	status := processingFailureStatus(err, phase)
	if status == 0 {
		return
	}
	if status == http.StatusRequestEntityTooLarge && request != nil && request.ProtoMajor == 1 {
		request.Close = true
		w.Header().Set("Connection", "close")
	}
	message := "HTTP processing failed"
	switch status {
	case http.StatusBadRequest:
		message = "invalid HTTP request"
	case http.StatusRequestEntityTooLarge:
		message = "request body exceeds the processing limit"
	case http.StatusServiceUnavailable:
		message = "HTTP processing capacity is unavailable"
	case http.StatusGatewayTimeout:
		message = "HTTP processing timed out"
	case http.StatusBadGateway:
		message = "upstream exchange failed"
	}
	http.Error(w, message, status)
}

func processingFailureStatus(err error, phase model.Phase) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	var processing *model.ProcessingError
	if errors.As(err, &processing) {
		switch processing.Kind {
		case model.ProcessingErrorCanceled:
			return 0
		case model.ProcessingErrorTimeout:
			return http.StatusGatewayTimeout
		case model.ProcessingErrorBodyLimitExceeded, model.ProcessingErrorOutputLimitExceeded:
			if phase == model.RequestPhase {
				return http.StatusRequestEntityTooLarge
			}
			return http.StatusBadGateway
		case model.ProcessingErrorCapacityExhausted, model.ProcessingErrorResourceLimit, model.ProcessingErrorGenerationRetired:
			return http.StatusServiceUnavailable
		case model.ProcessingErrorUpstream, model.ProcessingErrorBodyRead, model.ProcessingErrorProtocol, model.ProcessingErrorIrreversibleIOFailure:
			if processing.Origin == model.ProcessingOriginProcessor && phase == model.RequestPhase {
				return http.StatusInternalServerError
			}
			return http.StatusBadGateway
		case model.ProcessingErrorInvalidOutput, model.ProcessingErrorExecution, model.ProcessingErrorInvalidInput:
			if phase == model.ResponsePhase {
				return http.StatusBadGateway
			}
			return http.StatusInternalServerError
		case model.ProcessingErrorCleanupFailure:
			return http.StatusServiceUnavailable
		case model.ProcessingErrorClosed:
			return http.StatusServiceUnavailable
		default:
			return http.StatusInternalServerError
		}
	}
	switch {
	case errors.Is(err, model.ErrBodyLimit):
		if phase == model.RequestPhase {
			return http.StatusRequestEntityTooLarge
		}
		return http.StatusBadGateway
	case errors.Is(err, model.ErrCapacityExhausted), errors.Is(err, model.ErrResourceLimit):
		return http.StatusServiceUnavailable
	case errors.Is(err, model.ErrIrreversibleIO), errors.Is(err, model.ErrBodyUnavailable):
		return http.StatusBadGateway
	case errors.Is(err, model.ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func writeRejected(w http.ResponseWriter) {
	http.Error(w, "request rejected", http.StatusForbidden)
}

func writeSyntheticResponse(w http.ResponseWriter, request *http.Request, response model.SyntheticResponse) error {
	if w == nil || request == nil || response.Status() < http.StatusOK || response.Status() > 599 {
		return model.ErrInvalid
	}
	headers, err := modelHeaderToHTTP(response.Headers())
	if err != nil {
		return err
	}
	body, err := response.BodyBytesCopy()
	if err != nil {
		return err
	}
	trailers := response.Trailers()
	declared, err := trailers.Declared().Entries()
	if err != nil && trailers.Availability() != model.TrailerUnavailable {
		return err
	}
	trailerValues := http.Header{}
	if values, valuesErr := trailers.Values(); valuesErr == nil {
		entries, entriesErr := values.Entries()
		if entriesErr != nil {
			return entriesErr
		}
		for _, field := range entries {
			trailerValues[field.Name] = append([]string(nil), field.Values...)
		}
	}
	for name := range headers {
		if processingHopHeader(name) || strings.EqualFold(name, "Host") {
			delete(headers, name)
		}
	}
	for _, field := range declared {
		if !forbiddenResponseTrailer(field.Name) && !processingHopHeader(field.Name) {
			headers.Add("Trailer", field.Name)
		}
	}
	status := response.Status()
	bodyless := responseForbidsBody(status)
	if status == http.StatusNoContent {
		headers.Del("Content-Length")
	} else if status == http.StatusResetContent {
		headers.Set("Content-Length", "0")
	} else if status != http.StatusNotModified {
		headers.Set("Content-Length", strconv.Itoa(len(body)))
	}
	for name := range w.Header() {
		w.Header().Del(name)
	}
	for name, values := range headers {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(status)
	if request.Method != http.MethodHead && !bodyless && len(body) != 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	for name, values := range trailerValues {
		if !forbiddenResponseTrailer(name) {
			w.Header()[name] = append([]string(nil), values...)
		}
	}
	return nil
}
