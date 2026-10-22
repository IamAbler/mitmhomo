package httphook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ApplyResponse buffers only after a response rule matches. Complete reads
// replace the source with a replayable copy; oversized reads use a bounded
// prefix/source wrapper. An incomplete read closes the source, clears Body,
// and returns an error because the partial response is not safe to restore.
func (s *Snapshot) ApplyResponse(ctx context.Context, request *http.Request, response *http.Response) (ResponseResult, error) {
	if response == nil {
		return ResponseResult{}, nil
	}
	rule := s.matchingRule(ResponsePhase, request, response.Header, response.StatusCode)
	if rule == nil {
		return ResponseResult{}, nil
	}
	result := ResponseResult{Matched: true}
	if !s.tryAcquire() {
		result.Fallback = fallback(rule, errConcurrentLimit)
		return result, nil
	}
	defer s.active.Add(-1)
	if ctx == nil {
		ctx = context.Background()
	}
	body, complete, readErr, closeErr := readResponseBody(response, s.config.MaxBodyBytes)
	if readErr != nil {
		return result, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		result.Fallback = fallback(rule, fmt.Errorf("close response body after complete read: %w", closeErr))
		return result, nil
	}
	if !complete {
		result.Fallback = fallback(rule, errBodyLimit)
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	var value any
	var err error
	if rule.mode == APIMode {
		value, err = s.executeAPI(ctx, rule, apiResponseGlobals(request, response, body))
	} else {
		value, err = s.execute(ctx, rule, responseInput(request, response, body))
	}
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		result.Fallback = fallback(rule, err)
		return result, nil
	}
	result, err = parseResponseOutput(value, body, s.config.MaxBodyBytes, response.StatusCode)
	if err != nil {
		result = ResponseResult{Matched: true, Fallback: fallback(rule, err)}
	}
	return result, nil
}

func readResponseBody(response *http.Response, limit int) ([]byte, bool, error, error) {
	if response.Body == nil || response.Body == http.NoBody {
		return nil, true, nil, nil
	}
	original := response.Body
	body, err := io.ReadAll(io.LimitReader(original, int64(limit)+1))
	if err != nil {
		closeErr := original.Close()
		response.Body = http.NoBody
		return nil, false, err, closeErr
	}
	if len(body) > limit {
		response.Body = replayPrefix(body, original, true)
		return nil, false, nil, nil
	}
	closeErr := original.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	return body, true, nil, closeErr
}
