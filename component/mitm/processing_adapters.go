package mitm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/component/mitm/httphook"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
	"github.com/metacubex/mihomo/component/mitm/rewrite"
	"github.com/metacubex/mihomo/log"
)

type processingAdapterFunc func(context.Context, model.Input) (model.DoneResult, error)

// processingAdapter runs existing MITM behavior through the same immutable
// Input / DoneResult contract as other Processor backends.
type processingAdapter struct {
	descriptor processor.Descriptor
	lifecycle  *processor.Lifecycle
	execute    processingAdapterFunc
}

func newProcessingAdapter(descriptor processor.Descriptor, capacity int, execute processingAdapterFunc) (*processingAdapter, error) {
	lifecycle, err := processor.NewProcessorLifecycle(descriptor.ID, capacity)
	if err != nil {
		return nil, err
	}
	return &processingAdapter{descriptor: descriptor, lifecycle: lifecycle, execute: execute}, nil
}

func (p *processingAdapter) Describe() processor.Descriptor { return p.descriptor.Clone() }

func (p *processingAdapter) Start(ctx context.Context, input model.Input, resources ...io.Closer) (*processor.Invocation, error) {
	invocation, completion, err := p.lifecycle.BeginWithResources(ctx, input.Key(), resources...)
	if err != nil {
		return nil, err
	}
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				completion.Finish(model.DoneResult{}, model.NewProcessingError(
					model.ProcessingErrorExecution, model.ProcessingOriginProcessor,
					input.Key().Phase, p.descriptor.ID, input.Key().Invocation,
					fmt.Errorf("adapter panic: %v", recovered),
				))
			}
		}()
		result, runErr := p.execute(invocation.Context(), input)
		completion.Finish(result, runErr)
	}()
	return invocation, nil
}

func (p *processingAdapter) Close() error { return p.lifecycle.Close() }

func (p *processingAdapter) WaitClosed(ctx context.Context) error {
	return p.lifecycle.WaitClosed(ctx)
}

func legacyHookEntry(snapshot *httphook.Snapshot) (pipeline.Entry, error) {
	if snapshot == nil || !snapshot.HasPhase(httphook.RequestPhase) && !snapshot.HasPhase(httphook.ResponsePhase) {
		return pipeline.Entry{}, nil
	}
	maxBody := snapshot.MaxBodyBytes()
	descriptor := processor.Descriptor{
		ID: "legacy-http-script", Backend: "httphook-compat", ContractVersion: 1,
		Request: snapshot.HasPhase(httphook.RequestPhase), Response: snapshot.HasPhase(httphook.ResponsePhase),
	}
	if descriptor.Request {
		descriptor.RequestNeeds = processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: maxBody}
	}
	if descriptor.Response {
		descriptor.ResponseNeeds = processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: maxBody}
	}
	backend, err := newProcessingAdapter(descriptor, processor.DefaultInvocationCapacity, func(ctx context.Context, input model.Input) (model.DoneResult, error) {
		if input.Key().Phase == model.RequestPhase {
			body, err := input.Body().BytesCopy()
			if err != nil {
				return model.DoneResult{}, err
			}
			request, err := adapterRequest(input.Request(), body)
			if err != nil {
				return model.DoneResult{}, err
			}
			defer request.Body.Close()
			result, err := snapshot.ApplyRequestWithExternalBodyOwner(ctx, request)
			if err != nil {
				return model.DoneResult{}, err
			}
			if result.Fallback != nil {
				logLegacyFallback("request", result.Fallback)
				return model.Continue(), nil
			}
			return requestHookResult(input, result, snapshot.MaxBodyBytes())
		}

		request, err := adapterRequest(input.Request(), nil)
		if err != nil {
			return model.DoneResult{}, err
		}
		body, err := input.Body().BytesCopy()
		if err != nil {
			return model.DoneResult{}, err
		}
		responseHead, _ := input.Response()
		response, err := adapterResponse(responseHead, body)
		if err != nil {
			return model.DoneResult{}, err
		}
		defer request.Body.Close()
		defer response.Body.Close()
		result, err := snapshot.ApplyResponse(ctx, request, response)
		if err != nil {
			return model.DoneResult{}, err
		}
		if result.Fallback != nil {
			logLegacyFallback("response", result.Fallback)
			return model.Continue(), nil
		}
		return responseHookResult(input, result, snapshot.MaxBodyBytes())
	})
	if err != nil {
		return pipeline.Entry{}, err
	}
	return pipeline.Entry{
		Class: pipeline.Script, Priority: -1 << 30, Processor: backend,
		Profile:      pipeline.LegacyProfile,
		FailOpenSafe: func(error) bool { return false },
		Match: func(metadata pipeline.Metadata) bool {
			if metadata.Key.Phase == model.RequestPhase {
				request, err := adapterRequest(metadata.Request, nil)
				return err == nil && snapshot.MatchesRequest(request)
			}
			if metadata.Key.Phase == model.ResponsePhase && metadata.HasResponse {
				request, err := adapterRequest(metadata.Request, nil)
				if err != nil {
					return false
				}
				response, err := adapterResponse(metadata.Response, nil)
				return err == nil && snapshot.MatchesResponse(request, response)
			}
			return false
		},
	}, nil
}

func internalResponseHookEntry(hook ResponseHook) (pipeline.Entry, error) {
	if hook == nil {
		return pipeline.Entry{}, nil
	}
	const maxHookBody = model.DefaultBodyBufferBytes
	descriptor := processor.Descriptor{
		ID: "internal-response-hook", Backend: "internal-http-hook", ContractVersion: 1,
		Response:      true,
		ResponseNeeds: processor.Requirements{Body: model.FullBuffered, MaxBodyBytes: maxHookBody},
	}
	backend, err := newProcessingAdapter(descriptor, processor.DefaultInvocationCapacity, func(ctx context.Context, input model.Input) (model.DoneResult, error) {
		body, err := input.Body().BytesCopy()
		if err != nil {
			return model.DoneResult{}, err
		}
		request, err := adapterRequest(input.Request(), nil)
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, descriptor.ID, err)
		}
		responseHead, ok := input.Response()
		if !ok {
			return model.DoneResult{}, adapterProtocolError(input, descriptor.ID, model.ErrInvalid)
		}
		response, err := adapterResponse(responseHead, body)
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, descriptor.ID, err)
		}
		defer request.Body.Close()
		defer response.Body.Close()
		response.Request = request
		originalBody := response.Body
		originalContentLengthValue := response.ContentLength
		originalContentLength := append([]string(nil), response.Header.Values("Content-Length")...)
		if err := hook(response); err != nil {
			return model.DoneResult{}, fmt.Errorf("internal response hook: %w", err)
		}
		if !equalHeaderValues(originalContentLength, response.Header.Values("Content-Length")) || response.ContentLength != originalContentLengthValue {
			if framing, ok := ctx.Value(responseHookFramingKey{}).(*responseHookFraming); ok {
				values := response.Header.Values("Content-Length")
				if equalHeaderValues(originalContentLength, values) && response.ContentLength >= 0 {
					values = []string{fmt.Sprint(response.ContentLength)}
				}
				framing.record(values)
			}
		}
		patch := model.ResponsePatch{}
		if response.StatusCode != responseHead.Status {
			patch.Status = model.Optional[int]{Present: true, Value: response.StatusCode}
		}
		lease := model.NewCopyLease(input.Ledger())
		defer lease.Close()
		block, err := model.NewHeaderBlock(lease, ordinaryHeaderFields(response.Header))
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, descriptor.ID, err)
		}
		patch.Headers = []model.HeaderEdit{{Kind: model.HeaderReplaceAll, Block: block}}
		if response.Body != originalBody {
			if response.Body == nil {
				patch.Body = model.BodyEdit{Kind: model.BodyReplace, Bytes: []byte{}}
			} else {
				defer response.Body.Close()
				changedBody, err := io.ReadAll(io.LimitReader(response.Body, maxHookBody+1))
				if err != nil {
					return model.DoneResult{}, err
				}
				if int64(len(changedBody)) > maxHookBody {
					return model.DoneResult{}, model.ErrBodyLimit
				}
				patch.Body = model.BodyEdit{Kind: model.BodyReplace, Bytes: changedBody}
			}
		}
		done, err := model.ChangeResponse(patch, input.Ledger(), maxHookBody)
		if err != nil {
			return model.DoneResult{}, adapterResultError(input, descriptor.ID, err)
		}
		return done, nil
	})
	if err != nil {
		return pipeline.Entry{}, err
	}
	return pipeline.Entry{Class: pipeline.InternalHook, Priority: -1 << 30, Processor: backend}, nil
}

func rewriteEntries(snapshot *rewrite.Snapshot) ([]pipeline.Entry, error) {
	if snapshot == nil || !snapshot.HasRequestRules() && !snapshot.HasResponseRules() {
		return nil, nil
	}
	descriptor := processor.Descriptor{
		ID: "legacy-rewrite", Backend: "rewrite-compat", ContractVersion: 1,
		Request: snapshot.HasRequestRules(), Response: snapshot.HasResponseRules(),
	}
	backend, err := newProcessingAdapter(descriptor, processor.DefaultInvocationCapacity, func(ctx context.Context, input model.Input) (model.DoneResult, error) {
		request, err := adapterRewriteRequest(input.Request())
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, descriptor.ID, err)
		}
		if input.Key().Phase == model.RequestPhase {
			result, err := snapshot.ApplyRequest(ctx, request)
			if err != nil {
				return model.DoneResult{}, adapterProtocolError(input, descriptor.ID, err)
			}
			if result.Terminal != nil {
				return terminalDoneResult(input, descriptor.ID, result.Terminal)
			}
			if !result.Changed {
				return model.Continue(), nil
			}
			return rewriteRequestResult(input, descriptor.ID, result)
		}
		responseHead, ok := input.Response()
		if !ok {
			return model.DoneResult{}, adapterProtocolError(input, descriptor.ID, model.ErrInvalid)
		}
		responseHeaders, err := modelHeadersToMap(responseHead.Headers)
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, descriptor.ID, err)
		}
		result, err := snapshot.ApplyResponse(ctx, request, rewrite.ResponseView{StatusCode: responseHead.Status, Headers: responseHeaders})
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, descriptor.ID, err)
		}
		if !result.Changed {
			return model.Continue(), nil
		}
		return rewriteResponseResult(input, descriptor.ID, result)
	})
	if err != nil {
		return nil, err
	}
	return []pipeline.Entry{{Class: pipeline.Rewrite, Processor: backend}}, nil
}

func requestHookResult(input model.Input, result httphook.RequestResult, maxBodyBytes int64) (model.DoneResult, error) {
	lease := model.NewCopyLease(input.Ledger())
	defer lease.Close()
	patch := model.RequestPatch{}
	if result.Method != nil {
		patch.Method = model.Optional[string]{Present: true, Value: *result.Method}
	}
	if result.URL != nil {
		parsed, err := model.ParseURL(lease, result.URL.String(), model.MITMHTTPS)
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, "legacy-http-script", err)
		}
		patch.URL = model.Optional[model.URLValue]{Present: true, Value: parsed}
	}
	if result.Host != nil {
		patch.Authority = model.Optional[string]{Present: true, Value: *result.Host}
	}
	if result.Headers != nil {
		fields := ordinaryHeaderFields(*result.Headers)
		block, err := model.NewHeaderBlock(lease, fields)
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, "legacy-http-script", err)
		}
		patch.Headers = []model.HeaderEdit{{Kind: model.HeaderReplaceAll, Block: block}}
	}
	if result.BodyChanged {
		patch.Body = model.BodyEdit{Kind: model.BodyReplace, Bytes: result.Body}
	}
	if !requestPatchChanged(patch) {
		return model.Continue(), nil
	}
	done, err := model.ChangeRequest(patch, input.Ledger(), maxBodyBytes)
	if err != nil {
		return model.DoneResult{}, adapterResultError(input, "legacy-http-script", err)
	}
	return done, nil
}

func responseHookResult(input model.Input, result httphook.ResponseResult, maxBodyBytes int64) (model.DoneResult, error) {
	lease := model.NewCopyLease(input.Ledger())
	defer lease.Close()
	patch := model.ResponsePatch{}
	if result.Status != nil {
		patch.Status = model.Optional[int]{Present: true, Value: *result.Status}
	}
	if result.Headers != nil {
		block, err := model.NewHeaderBlock(lease, ordinaryHeaderFields(*result.Headers))
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, "legacy-http-script", err)
		}
		patch.Headers = []model.HeaderEdit{{Kind: model.HeaderReplaceAll, Block: block}}
	}
	if result.BodyChanged {
		patch.Body = model.BodyEdit{Kind: model.BodyReplace, Bytes: result.Body}
	}
	if len(patch.Headers) == 0 && !patch.Status.Present && patch.Body.Kind == model.BodyKeep {
		return model.Continue(), nil
	}
	done, err := model.ChangeResponse(patch, input.Ledger(), maxBodyBytes)
	if err != nil {
		return model.DoneResult{}, adapterResultError(input, "legacy-http-script", err)
	}
	return done, nil
}

func rewriteRequestResult(input model.Input, id string, result rewrite.RequestResult) (model.DoneResult, error) {
	lease := model.NewCopyLease(input.Ledger())
	defer lease.Close()
	current := input.Request()
	patch := model.RequestPatch{}
	if result.Request.Method != current.Method {
		patch.Method = model.Optional[string]{Present: true, Value: result.Request.Method}
	}
	if result.Request.URL.String() != current.URL.String() {
		parsed, err := model.ParseURL(lease, result.Request.URL.String(), current.URL.Profile())
		if err != nil {
			return model.DoneResult{}, adapterProtocolError(input, id, err)
		}
		patch.URL = model.Optional[model.URLValue]{Present: true, Value: parsed}
		if !sameURLAuthority(current.URL.Host(), result.Request.URL.Host) {
			patch.Authority = model.Optional[string]{Present: true, Value: result.Request.URL.Host}
		}
	}
	fields := rewriteHeaderFields(result.Request.Headers, false)
	if result.Body != nil {
		oldType, _, _ := current.Headers.Values("Content-Type")
		newType := result.Request.Headers["Content-Type"]
		if result.Body.ContentType != "" {
			result.Request.Headers["Content-Type"] = []string{result.Body.ContentType}
		} else if equalHeaderValues(oldType, newType) {
			delete(result.Request.Headers, "Content-Type")
		}
		for _, name := range []string{"Expect", "Content-Encoding", "Content-MD5", "Digest", "Content-Range"} {
			deleteHeaderMap(http.Header(result.Request.Headers), name)
		}
		fields = rewriteHeaderFields(result.Request.Headers, false)
		patch.Body = model.BodyEdit{Kind: model.BodyReplace, Bytes: []byte(result.Body.Replace)}
	}
	block, err := model.NewHeaderBlock(lease, fields)
	if err != nil {
		return model.DoneResult{}, adapterProtocolError(input, id, err)
	}
	patch.Headers = []model.HeaderEdit{{Kind: model.HeaderReplaceAll, Block: block}}
	done, err := model.ChangeRequest(patch, input.Ledger(), rewrite.DefaultMaxReplacementBodyBytes)
	if err != nil {
		return model.DoneResult{}, adapterResultError(input, id, err)
	}
	return done, nil
}

func rewriteResponseResult(input model.Input, id string, result rewrite.ResponseResult) (model.DoneResult, error) {
	lease := model.NewCopyLease(input.Ledger())
	defer lease.Close()
	current, _ := input.Response()
	patch := model.ResponsePatch{}
	if result.Response.StatusCode != current.Status {
		patch.Status = model.Optional[int]{Present: true, Value: result.Response.StatusCode}
	}
	if result.Body != nil {
		clearReplacedRepresentationHeaders(http.Header(result.Response.Headers))
	}
	fields := rewriteHeaderFields(result.Response.Headers, false)
	if result.Body != nil {
		patch.Body = model.BodyEdit{Kind: model.BodyReplace, Bytes: []byte(result.Body.Replace)}
	}
	block, err := model.NewHeaderBlock(lease, fields)
	if err != nil {
		return model.DoneResult{}, adapterProtocolError(input, id, err)
	}
	patch.Headers = []model.HeaderEdit{{Kind: model.HeaderReplaceAll, Block: block}}
	done, err := model.ChangeResponse(patch, input.Ledger(), rewrite.DefaultMaxReplacementBodyBytes)
	if err != nil {
		return model.DoneResult{}, adapterResultError(input, id, err)
	}
	return done, nil
}

func terminalDoneResult(input model.Input, id string, terminal *rewrite.TerminalResponse) (model.DoneResult, error) {
	if terminal == nil {
		return model.DoneResult{}, adapterProtocolError(input, id, model.ErrInvalid)
	}
	lease := model.NewCopyLease(input.Ledger())
	defer lease.Close()
	headers, err := model.NewHeaderBlock(lease, rewriteHeaderFields(terminal.Headers, false))
	if err != nil {
		return model.DoneResult{}, adapterProtocolError(input, id, err)
	}
	trailers, err := model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
	if err != nil {
		return model.DoneResult{}, adapterProtocolError(input, id, err)
	}
	synthetic, err := model.NewSyntheticResponse(terminal.StatusCode, headers, []byte(terminal.Body), trailers, input.Ledger(), model.DefaultProcessorOutputBytes)
	if err != nil {
		return model.DoneResult{}, adapterProtocolError(input, id, err)
	}
	result, err := model.Respond(synthetic)
	if err != nil {
		return model.DoneResult{}, adapterProtocolError(input, id, err)
	}
	return result, nil
}

func adapterRequest(head model.RequestHead, body []byte) (*http.Request, error) {
	target, err := url.Parse(head.URL.String())
	if err != nil || target == nil {
		return nil, model.ErrInvalid
	}
	header, err := modelHeaderToHTTP(head.Headers)
	if err != nil {
		return nil, err
	}
	requestBody := io.ReadCloser(http.NoBody)
	if len(body) != 0 {
		requestBody = io.NopCloser(bytes.NewReader(body))
	}
	return &http.Request{Method: head.Method, URL: target, Host: head.Authority, Header: header, Body: requestBody, ContentLength: int64(len(body)), RequestURI: ""}, nil
}

func adapterResponse(head model.ResponseHead, body []byte) (*http.Response, error) {
	header, err := modelHeaderToHTTP(head.Headers)
	if err != nil {
		return nil, err
	}
	responseBody := io.ReadCloser(http.NoBody)
	if len(body) != 0 {
		responseBody = io.NopCloser(bytes.NewReader(body))
	}
	return &http.Response{StatusCode: head.Status, Status: responseStatus(head.Status), Header: header, Body: responseBody, ContentLength: int64(len(body)), Trailer: make(http.Header)}, nil
}

func adapterRewriteRequest(head model.RequestHead) (rewrite.RequestView, error) {
	target, err := url.Parse(head.URL.String())
	if err != nil || target == nil {
		return rewrite.RequestView{}, model.ErrInvalid
	}
	headers, err := modelHeadersToMap(head.Headers)
	if err != nil {
		return rewrite.RequestView{}, err
	}
	if head.Authority != "" {
		headers["Host"] = []string{head.Authority}
	}
	return rewrite.RequestView{Method: head.Method, URL: *target, Headers: headers}, nil
}

func modelHeaderToHTTP(block model.HeaderBlock) (http.Header, error) {
	entries, err := block.Entries()
	if err != nil {
		return nil, err
	}
	header := make(http.Header, len(entries))
	for _, field := range entries {
		header[field.Name] = append([]string(nil), field.Values...)
	}
	return header, nil
}

func modelHeadersToMap(block model.HeaderBlock) (rewrite.HeaderMap, error) {
	entries, err := block.Entries()
	if err != nil {
		return nil, err
	}
	headers := make(rewrite.HeaderMap, len(entries))
	for _, field := range entries {
		headers[field.Name] = append([]string(nil), field.Values...)
	}
	return headers, nil
}

func ordinaryHeaderFields(header http.Header) []model.HeaderField {
	fields := make([]model.HeaderField, 0, len(header))
	connectionNamed := make(map[string]struct{})
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = http.CanonicalHeaderKey(strings.TrimSpace(name)); name != "" {
				connectionNamed[name] = struct{}{}
			}
		}
	}
	for _, name := range sortedHeaderNames(header) {
		if processingHopHeader(name) || strings.EqualFold(name, "Host") {
			continue
		}
		if _, nominated := connectionNamed[http.CanonicalHeaderKey(name)]; nominated {
			continue
		}
		fields = append(fields, model.HeaderField{Name: name, Values: append([]string(nil), header[name]...)})
	}
	return fields
}

func rewriteHeaderFields(headers rewrite.HeaderMap, allowHost bool) []model.HeaderField {
	fields := make([]model.HeaderField, 0, len(headers))
	connectionNamed := make(map[string]struct{})
	for _, value := range headers["Connection"] {
		for _, name := range strings.Split(value, ",") {
			if name = http.CanonicalHeaderKey(strings.TrimSpace(name)); name != "" {
				connectionNamed[name] = struct{}{}
			}
		}
	}
	for _, name := range sortedHeaderNames(http.Header(headers)) {
		if processingHopHeader(name) || !allowHost && strings.EqualFold(name, "Host") {
			continue
		}
		if _, nominated := connectionNamed[http.CanonicalHeaderKey(name)]; nominated {
			continue
		}
		fields = append(fields, model.HeaderField{Name: name, Values: append([]string(nil), headers[name]...)})
	}
	return fields
}

func sortedHeaderNames(header http.Header) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func processingHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "transfer-encoding", "trailer", "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "proxy-authentication-info", "te", "upgrade":
		return true
	default:
		return strings.HasPrefix(name, ":")
	}
}

func requestPatchChanged(patch model.RequestPatch) bool {
	return patch.Method.Present || patch.URL.Present || patch.Authority.Present || len(patch.Headers) != 0 || patch.Body.Kind == model.BodyReplace || len(patch.Trailers) != 0
}

func adapterResultError(input model.Input, id string, err error) error {
	kind := model.ProcessingErrorInvalidOutput
	if errors.Is(err, model.ErrResourceLimit) || errors.Is(err, model.ErrOutputLimit) {
		kind = model.ProcessingErrorResourceLimit
	}
	return model.NewProcessingError(kind, model.ProcessingOriginProcessor, input.Key().Phase, id, input.Key().Invocation, err)
}

func adapterProtocolError(input model.Input, id string, err error) error {
	return model.NewProcessingError(model.ProcessingErrorProtocol, model.ProcessingOriginProtocol, input.Key().Phase, id, input.Key().Invocation, err)
}

func logLegacyFallback(phase string, err error) {
	log.Warnln("MITM HTTP %s script hook fallback: %s", phase, err)
}

func deleteHeaderMap(header http.Header, name string) {
	for key := range header {
		if strings.EqualFold(key, name) {
			delete(header, key)
		}
	}
}
