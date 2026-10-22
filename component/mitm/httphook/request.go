package httphook

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
)

var (
	errBodyLimit       = errors.New("HTTP body exceeds script hook buffer limit")
	errConcurrentLimit = errors.New("HTTP script hook concurrency limit reached")
)

// ApplyRequest buffers only after a rule matches. After a match it owns the
// original Body: complete reads close it before installing a replay copy, and
// partial reads transfer it to a replay Body that closes the source when the
// caller closes the request Body. Callers should close request.Body as usual.
func (s *Snapshot) ApplyRequest(ctx context.Context, request *http.Request) (RequestResult, error) {
	return s.applyRequest(ctx, request, true)
}

// ApplyRequestWithExternalBodyOwner is for requests whose original Body is
// closed by an enclosing owner, such as net/http.Server after an inbound
// handler returns. It leaves that original Body open after buffering and does
// not close it from a replay wrapper.
func (s *Snapshot) ApplyRequestWithExternalBodyOwner(ctx context.Context, request *http.Request) (RequestResult, error) {
	return s.applyRequest(ctx, request, false)
}

func (s *Snapshot) applyRequest(ctx context.Context, request *http.Request, closeOriginalBody bool) (RequestResult, error) {
	if s == nil || request == nil {
		return RequestResult{}, nil
	}
	rule := s.matchingRule(RequestPhase, request, request.Header, 0)
	if rule == nil {
		return RequestResult{}, nil
	}
	result := RequestResult{Matched: true}
	if !s.tryAcquire() {
		result.Fallback = fallback(rule, errConcurrentLimit)
		return result, nil
	}
	defer s.active.Add(-1)
	if ctx == nil {
		ctx = context.Background()
	}
	body, complete, err := readRequestBody(request, s.config.MaxBodyBytes, closeOriginalBody)
	if err != nil {
		return result, err
	}
	if !complete {
		result.Fallback = fallback(rule, errBodyLimit)
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	value, err := s.execute(ctx, rule, requestInput(request, body))
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		result.Fallback = fallback(rule, err)
		return result, nil
	}
	result, err = parseRequestOutput(value, request, body, s.config.MaxBodyBytes)
	if err != nil {
		result = RequestResult{Matched: true, Fallback: fallback(rule, err)}
	}
	return result, nil
}

func readRequestBody(request *http.Request, limit int, closeOriginal bool) ([]byte, bool, error) {
	if request == nil || request.Body == nil || request.Body == http.NoBody {
		return nil, true, nil
	}
	original := request.Body
	body, err := io.ReadAll(io.LimitReader(original, int64(limit)+1))
	if err != nil {
		request.Body = replayPrefix(body, original, closeOriginal)
		return nil, false, err
	}
	if len(body) > limit {
		request.Body = replayPrefix(body, original, closeOriginal)
		return nil, false, nil
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	if closeOriginal {
		if err := original.Close(); err != nil {
			return body, true, err
		}
	}
	return body, true, nil
}

type replayBody struct {
	reader          io.Reader
	closer          io.Closer
	closeUnderlying bool
	closeOnce       sync.Once
	closeErr        error
}

func replayPrefix(prefix []byte, remaining io.ReadCloser, closeUnderlying bool) io.ReadCloser {
	return &replayBody{
		reader:          io.MultiReader(bytes.NewReader(prefix), remaining),
		closer:          remaining,
		closeUnderlying: closeUnderlying,
	}
}

func (b *replayBody) Read(buffer []byte) (int, error) { return b.reader.Read(buffer) }
func (b *replayBody) Close() error {
	if b.closeUnderlying && b.closer != nil {
		b.closeOnce.Do(func() { b.closeErr = b.closer.Close() })
	}
	return b.closeErr
}
