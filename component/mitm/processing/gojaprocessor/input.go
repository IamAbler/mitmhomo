package gojaprocessor

import (
	"encoding/base64"
	"fmt"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

func makeInput(input model.Input, needs processor.Requirements) (map[string]any, error) {
	key := input.Key()
	request, err := requestObject(input.Request())
	if err != nil {
		return nil, err
	}
	view := map[string]any{
		"version": apiVersion,
		"phase":   phaseName(key.Phase),
		"key": map[string]any{
			"transactionId": key.TransactionID,
			"generation":    fmt.Sprint(uint64(key.Generation)),
			"phase":         phaseName(key.Phase),
			"revision":      fmt.Sprint(uint64(key.Revision)),
			"invocationId":  string(key.Invocation),
		},
		"connection": connectionObject(input.Connection()),
		"route":      routeObject(input.Route()),
		"origin":     originName(input.Origin()),
		"request":    request,
	}
	if response, ok := input.Response(); ok {
		responseView, err := responseObject(response)
		if err != nil {
			return nil, err
		}
		view["response"] = responseView
	}
	body, err := bodyObject(input.Body(), needs.Body == model.FullBuffered, needs.MaxBodyBytes)
	if err != nil {
		return nil, err
	}
	view["body"] = body
	return view, nil
}

func requestObject(head model.RequestHead) (map[string]any, error) {
	headers, err := headerFields(head.Headers)
	if err != nil {
		return nil, err
	}
	trailers, err := trailerObject(head.Trailers)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"method":    head.Method,
		"url":       head.URL.String(),
		"authority": head.Authority,
		"headers":   headers,
		"trailers":  trailers,
	}, nil
}

func responseObject(head model.ResponseHead) (map[string]any, error) {
	headers, err := headerFields(head.Headers)
	if err != nil {
		return nil, err
	}
	trailers, err := trailerObject(head.Trailers)
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": head.Status, "headers": headers, "trailers": trailers}, nil
}

func connectionObject(connection model.ConnectionView) map[string]any {
	return map[string]any{
		"id":          connection.ID,
		"streamId":    connection.StreamID,
		"source":      connection.Source,
		"destination": connection.Destination,
		"sni":         connection.SNI,
		"inbound":     connection.Inbound,
		"downstream":  protocolObject(connection.Downstream),
		"upstream":    protocolObject(connection.Upstream),
	}
}

func protocolObject(protocol model.ProtocolInfo) map[string]any {
	return map[string]any{
		"major": protocol.Major,
		"minor": protocol.Minor,
		"alpn":  protocol.ALPN,
		"known": protocol.Known,
	}
}

func routeObject(route model.RouteView) map[string]any {
	return map[string]any{
		"known":    route.Known,
		"target":   route.Target,
		"leaseId":  route.LeaseID,
		"outbound": route.Outbound,
	}
}

func headerFields(block model.HeaderBlock) ([]any, error) {
	entries, err := block.Entries()
	if err != nil {
		return nil, err
	}
	fields := make([]any, 0, len(entries))
	for _, entry := range entries {
		fields = append(fields, map[string]any{"name": entry.Name, "values": entry.Values})
	}
	return fields, nil
}

func trailerObject(trailers model.TrailerView) (map[string]any, error) {
	declared, err := headerFields(trailers.Declared())
	if err != nil {
		return nil, err
	}
	out := map[string]any{"availability": trailerAvailabilityName(trailers.Availability()), "declared": declared}
	if trailers.Availability() == model.TrailerComplete {
		values, err := trailers.Values()
		if err != nil {
			return nil, err
		}
		fields, err := headerFields(values)
		if err != nil {
			return nil, err
		}
		out["values"] = fields
	}
	return out, nil
}

func bodyObject(body model.BodyView, includeBytes bool, maxBytes int64) (map[string]any, error) {
	info := body.Info()
	out := map[string]any{
		"state":               bodyStateName(info.State),
		"owner":               ownerName(info.Owner),
		"length":              info.Length,
		"claimed":             info.Claimed,
		"needsServerDisposal": info.NeedsServerDisposal,
		"available":           false,
	}
	if !includeBytes || info.State != model.FullBufferedState && info.State != model.Replaced {
		return out, nil
	}
	if maxBytes >= 0 && info.Length > maxBytes {
		return nil, model.ErrBodyLimit
	}
	data, err := body.BytesCopy()
	if err != nil {
		return nil, err
	}
	if maxBytes >= 0 && int64(len(data)) > maxBytes {
		return nil, model.ErrBodyLimit
	}
	out["available"] = true
	out["encoding"] = "base64"
	out["base64"] = base64.StdEncoding.EncodeToString(data)
	return out, nil
}

func phaseName(phase model.Phase) string {
	if phase == model.RequestPhase {
		return "request"
	}
	if phase == model.ResponsePhase {
		return "response"
	}
	return "invalid"
}

func originName(origin model.ResponseOrigin) string {
	switch origin {
	case model.OriginUpstream:
		return "upstream"
	case model.OriginSynthetic:
		return "synthetic"
	case model.OriginPolicy:
		return "policy"
	default:
		return "unknown"
	}
}

func bodyStateName(state model.BodyState) string {
	switch state {
	case model.Unavailable:
		return "unavailable"
	case model.UnreadStream:
		return "unread_stream"
	case model.PrefixReplay:
		return "prefix_replay"
	case model.FullBufferedState:
		return "full_buffered"
	case model.Replaced:
		return "replaced"
	case model.Faulted:
		return "faulted"
	case model.Released:
		return "released"
	case model.Reading:
		return "reading"
	default:
		return "unknown"
	}
}

func ownerName(owner model.OwnerKind) string {
	switch owner {
	case model.ServerOwned:
		return "server"
	case model.TransportOwned:
		return "transport"
	case model.FrameworkOwned:
		return "framework"
	default:
		return "unknown"
	}
}

func trailerAvailabilityName(availability model.TrailerAvailability) string {
	switch availability {
	case model.TrailerPending:
		return "pending"
	case model.TrailerComplete:
		return "complete"
	default:
		return "unavailable"
	}
}
