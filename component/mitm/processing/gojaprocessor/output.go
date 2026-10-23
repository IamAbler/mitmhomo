package gojaprocessor

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

func decodeResult(input model.Input, value any, maxBodyBytes int64) (model.DoneResult, error) {
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return model.DoneResult{}, fmt.Errorf("result must be an object")
	}
	kind, ok := object["kind"].(string)
	if !ok {
		return model.DoneResult{}, fmt.Errorf("result.kind must be a string")
	}
	ledger := input.Ledger()
	if ledger == nil {
		return model.DoneResult{}, model.ErrInvalid
	}
	conversionLease := model.NewCopyLease(ledger)
	defer conversionLease.Close()

	var result model.DoneResult
	var err error
	switch kind {
	case "continue":
		if err = onlyKeys(object, "kind"); err == nil {
			result = model.Continue()
		}
	case "stop_phase":
		if err = onlyKeys(object, "kind"); err == nil {
			result = model.StopPhase()
		}
	case "reject":
		if err = onlyKeys(object, "kind", "code"); err == nil {
			var code string
			code, err = stringField(object, "code", true)
			if err == nil {
				result, err = model.Reject(code, ledger)
			}
		}
	case "abort":
		if err = onlyKeys(object, "kind", "reason"); err == nil {
			var reason string
			reason, err = stringField(object, "reason", true)
			if err == nil {
				result, err = model.Abort(reason, ledger)
			}
		}
	case "request_change":
		if err = onlyKeys(object, "kind", "request"); err == nil {
			var request map[string]any
			request, err = objectField(object, "request", true)
			if err == nil {
				var patch model.RequestPatch
				patch, err = requestPatch(conversionLease, input, request, maxBodyBytes)
				if err == nil {
					result, err = model.ChangeRequest(patch, ledger, maxBodyBytes)
				}
			}
		}
	case "response_change":
		if err = onlyKeys(object, "kind", "response"); err == nil {
			var response map[string]any
			response, err = objectField(object, "response", true)
			if err == nil {
				var patch model.ResponsePatch
				patch, err = responsePatch(response, maxBodyBytes)
				if err == nil {
					result, err = model.ChangeResponse(patch, ledger, maxBodyBytes)
				}
			}
		}
	case "respond":
		if err = onlyKeys(object, "kind", "response"); err == nil {
			var response map[string]any
			response, err = objectField(object, "response", true)
			if err == nil {
				var synthetic model.SyntheticResponse
				synthetic, err = syntheticResponse(conversionLease, ledger, response, maxBodyBytes)
				if err == nil {
					result, err = model.Respond(synthetic)
					if err != nil {
						_ = synthetic.Release()
					}
				}
			}
		}
	default:
		err = fmt.Errorf("unsupported result kind %q", kind)
	}
	if err != nil {
		return model.DoneResult{}, err
	}
	return result, nil
}

func requestPatch(lease *model.CopyLease, input model.Input, object map[string]any, maxBodyBytes int64) (model.RequestPatch, error) {
	if err := onlyKeys(object, "method", "url", "authority", "headers", "trailers", "body"); err != nil {
		return model.RequestPatch{}, err
	}
	var patch model.RequestPatch
	if value, ok := object["method"]; ok {
		method, ok := value.(string)
		if !ok {
			return patch, fmt.Errorf("request.method must be a string")
		}
		patch.Method = model.Optional[string]{Present: true, Value: method}
	}
	if value, ok := object["url"]; ok {
		text, ok := value.(string)
		if !ok {
			return patch, fmt.Errorf("request.url must be a string")
		}
		url, err := model.ParseURL(lease, text, input.Request().URL.Profile())
		if err != nil {
			return patch, fmt.Errorf("request.url: %w", err)
		}
		patch.URL = model.Optional[model.URLValue]{Present: true, Value: url}
	}
	if value, ok := object["authority"]; ok {
		authority, ok := value.(string)
		if !ok {
			return patch, fmt.Errorf("request.authority must be a string")
		}
		patch.Authority = model.Optional[string]{Present: true, Value: authority}
	}
	var err error
	if value, ok := object["headers"]; ok {
		patch.Headers, err = headerEdits(value)
		if err != nil {
			return patch, fmt.Errorf("request.headers: %w", err)
		}
	}
	if value, ok := object["trailers"]; ok {
		patch.Trailers, err = headerEdits(value)
		if err != nil {
			return patch, fmt.Errorf("request.trailers: %w", err)
		}
	}
	if value, ok := object["body"]; ok {
		patch.Body.Bytes, err = bodyBytes(value, maxBodyBytes)
		if err != nil {
			return patch, fmt.Errorf("request.body: %w", err)
		}
		patch.Body.Kind = model.BodyReplace
	}
	return patch, nil
}

func responsePatch(object map[string]any, maxBodyBytes int64) (model.ResponsePatch, error) {
	if err := onlyKeys(object, "status", "headers", "trailers", "body"); err != nil {
		return model.ResponsePatch{}, err
	}
	var patch model.ResponsePatch
	if value, ok := object["status"]; ok {
		status, err := integerValue(value, 200, 599)
		if err != nil {
			return patch, fmt.Errorf("response.status: %w", err)
		}
		patch.Status = model.Optional[int]{Present: true, Value: status}
	}
	var err error
	if value, ok := object["headers"]; ok {
		patch.Headers, err = headerEdits(value)
		if err != nil {
			return patch, fmt.Errorf("response.headers: %w", err)
		}
	}
	if value, ok := object["trailers"]; ok {
		patch.Trailers, err = headerEdits(value)
		if err != nil {
			return patch, fmt.Errorf("response.trailers: %w", err)
		}
	}
	if value, ok := object["body"]; ok {
		patch.Body.Bytes, err = bodyBytes(value, maxBodyBytes)
		if err != nil {
			return patch, fmt.Errorf("response.body: %w", err)
		}
		patch.Body.Kind = model.BodyReplace
	}
	return patch, nil
}

func syntheticResponse(lease *model.CopyLease, ledger *model.Ledger, object map[string]any, maxBodyBytes int64) (model.SyntheticResponse, error) {
	if err := onlyKeys(object, "status", "headers", "body", "trailers"); err != nil {
		return model.SyntheticResponse{}, err
	}
	status, err := integerField(object, "status", 200, 599, true)
	if err != nil {
		return model.SyntheticResponse{}, err
	}
	headerValue, ok := object["headers"]
	if !ok {
		return model.SyntheticResponse{}, fmt.Errorf("response.headers is required")
	}
	fields, err := headerFieldsFromValue(headerValue)
	if err != nil {
		return model.SyntheticResponse{}, fmt.Errorf("response.headers: %w", err)
	}
	headers, err := model.NewHeaderBlock(lease, fields)
	if err != nil {
		return model.SyntheticResponse{}, err
	}
	bodyValue, ok := object["body"]
	if !ok {
		return model.SyntheticResponse{}, fmt.Errorf("response.body is required")
	}
	body, err := bodyBytes(bodyValue, maxBodyBytes)
	if err != nil {
		return model.SyntheticResponse{}, fmt.Errorf("response.body: %w", err)
	}
	trailers := model.TrailerView{}
	if trailerValue, ok := object["trailers"]; ok {
		trailerObject, ok := trailerValue.(map[string]any)
		if !ok || trailerObject == nil {
			return model.SyntheticResponse{}, fmt.Errorf("response.trailers must be an object")
		}
		if err := onlyKeys(trailerObject, "declared", "values"); err != nil {
			return model.SyntheticResponse{}, fmt.Errorf("response.trailers: %w", err)
		}
		declaredValue, hasDeclared := trailerObject["declared"]
		valuesValue, hasValues := trailerObject["values"]
		if !hasDeclared || !hasValues {
			return model.SyntheticResponse{}, fmt.Errorf("response.trailers requires declared and values")
		}
		declaredFields, err := headerFieldsFromValue(declaredValue)
		if err != nil {
			return model.SyntheticResponse{}, fmt.Errorf("response.trailers.declared: %w", err)
		}
		valueFields, err := headerFieldsFromValue(valuesValue)
		if err != nil {
			return model.SyntheticResponse{}, fmt.Errorf("response.trailers.values: %w", err)
		}
		declared, err := model.NewHeaderBlock(lease, declaredFields)
		if err != nil {
			return model.SyntheticResponse{}, err
		}
		values, err := model.NewHeaderBlock(lease, valueFields)
		if err != nil {
			return model.SyntheticResponse{}, err
		}
		trailers, err = model.NewTrailerView(model.TrailerComplete, declared, values)
		if err != nil {
			return model.SyntheticResponse{}, err
		}
	} else {
		trailers, err = model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
		if err != nil {
			return model.SyntheticResponse{}, err
		}
	}
	return model.NewSyntheticResponse(status, headers, body, trailers, ledger, maxBodyBytes)
}

func headerEdits(value any) ([]model.HeaderEdit, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("must be an array")
	}
	edits := make([]model.HeaderEdit, 0, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok || object == nil {
			return nil, fmt.Errorf("item %d must be an object", index)
		}
		op, ok := object["op"].(string)
		if !ok {
			return nil, fmt.Errorf("item %d op must be a string", index)
		}
		name, err := stringField(object, "name", true)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", index, err)
		}
		switch op {
		case "remove":
			if err := onlyKeys(object, "op", "name"); err != nil {
				return nil, fmt.Errorf("item %d: %w", index, err)
			}
			edits = append(edits, model.HeaderEdit{Kind: model.HeaderRemove, Name: name})
		case "set", "add":
			if err := onlyKeys(object, "op", "name", "values"); err != nil {
				return nil, fmt.Errorf("item %d: %w", index, err)
			}
			values, err := stringArrayField(object, "values", true)
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", index, err)
			}
			kind := model.HeaderSet
			if op == "add" {
				kind = model.HeaderAdd
			}
			edits = append(edits, model.HeaderEdit{Kind: kind, Name: name, Values: values})
		default:
			return nil, fmt.Errorf("item %d has unsupported header operation %q", index, op)
		}
	}
	return edits, nil
}

func headerFieldsFromValue(value any) ([]model.HeaderField, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("must be an array")
	}
	fields := make([]model.HeaderField, 0, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok || object == nil {
			return nil, fmt.Errorf("item %d must be an object", index)
		}
		if err := onlyKeys(object, "name", "values"); err != nil {
			return nil, fmt.Errorf("item %d: %w", index, err)
		}
		name, err := stringField(object, "name", true)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", index, err)
		}
		values, err := stringArrayField(object, "values", true)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", index, err)
		}
		fields = append(fields, model.HeaderField{Name: name, Values: values})
	}
	return fields, nil
}

func bodyBytes(value any, maxBytes int64) ([]byte, error) {
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return nil, fmt.Errorf("must be an object {encoding: \"base64\", data: string}")
	}
	if err := onlyKeys(object, "encoding", "data"); err != nil {
		return nil, err
	}
	encoding, err := stringField(object, "encoding", true)
	if err != nil || encoding != "base64" {
		return nil, fmt.Errorf("encoding must be \"base64\"")
	}
	encoded, err := stringField(object, "data", true)
	if err != nil {
		return nil, err
	}
	maxEncoded := int64(base64.StdEncoding.EncodedLen(int(maxBytes)))
	if int64(len(encoded)) > maxEncoded {
		return nil, model.ErrBodyLimit
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid standard base64: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, model.ErrBodyLimit
	}
	return data, nil
}

func onlyKeys(object map[string]any, allowed ...string) error {
	for key := range object {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unsupported field %q", key)
		}
	}
	return nil
}

func objectField(object map[string]any, key string, required bool) (map[string]any, error) {
	value, ok := object[key]
	if !ok {
		if required {
			return nil, fmt.Errorf("%s is required", key)
		}
		return nil, nil
	}
	child, ok := value.(map[string]any)
	if !ok || child == nil {
		return nil, fmt.Errorf("%s must be an object", key)
	}
	return child, nil
}

func stringField(object map[string]any, key string, required bool) (string, error) {
	value, ok := object[key]
	if !ok {
		if required {
			return "", fmt.Errorf("%s is required", key)
		}
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return text, nil
}

func stringArrayField(object map[string]any, key string, required bool) ([]string, error) {
	value, ok := object[key]
	if !ok {
		if required {
			return nil, fmt.Errorf("%s is required", key)
		}
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array of strings", key)
	}
	values := make([]string, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a string", key, index)
		}
		values[index] = text
	}
	return values, nil
}

func integerField(object map[string]any, key string, minimum, maximum int, required bool) (int, error) {
	value, ok := object[key]
	if !ok {
		if required {
			return 0, fmt.Errorf("%s is required", key)
		}
		return 0, nil
	}
	return integerValue(value, minimum, maximum)
}

func integerValue(value any, minimum, maximum int) (int, error) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || number < float64(minimum) || number > float64(maximum) {
		return 0, fmt.Errorf("must be an integer from %d through %d", minimum, maximum)
	}
	return int(number), nil
}

func outputLimitError(err error) bool {
	return errors.Is(err, model.ErrResourceLimit) || errors.Is(err, model.ErrBodyLimit) || errors.Is(err, model.ErrOutputLimit)
}
