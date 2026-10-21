// Package rewrite compiles immutable HTTP rewrite rules. It has no transport,
// socket or body reader access; adapters own framing and resource lifetimes.
package rewrite

import (
	"context"
	"net/url"
)

const (
	DefaultMaxReplacementBodyBytes      = 1 << 20
	DefaultMaxTotalReplacementBodyBytes = 16 << 20
)

type HeaderMap map[string][]string

type Config struct {
	Enable                       bool   `yaml:"enable" json:"enable"`
	MaxReplacementBodyBytes      int    `yaml:"max-replacement-body-bytes" json:"max-replacement-body-bytes"`
	MaxTotalReplacementBodyBytes int    `yaml:"max-total-replacement-body-bytes" json:"max-total-replacement-body-bytes"`
	Rules                        []Rule `yaml:"rules" json:"rules"`
}

type Rule struct {
	Name          string          `yaml:"name" json:"name"`
	Enabled       *bool           `yaml:"enabled" json:"enabled"`
	Match         Match           `yaml:"match" json:"match"`
	Request       *RequestAction  `yaml:"request" json:"request"`
	Response      *ResponseAction `yaml:"response" json:"response"`
	Redirect      *Redirect       `yaml:"redirect" json:"redirect"`
	LocalResponse *LocalResponse  `yaml:"local-response" json:"local-response"`
}

type Match struct {
	Domains    []string `yaml:"domains" json:"domains"`
	Path       string   `yaml:"path" json:"path"`
	PathPrefix string   `yaml:"path-prefix" json:"path-prefix"`
	PathRegex  string   `yaml:"path-regex" json:"path-regex"`
	Methods    []string `yaml:"methods" json:"methods"`
	// Headers matches phase-local headers: request headers in the request phase,
	// response headers in the response phase. All configured fields must match.
	Headers        map[string]string `yaml:"headers" json:"headers"`
	ResponseStatus []int             `yaml:"response-status" json:"response-status"`
}

type HeaderAction struct {
	Set    map[string]string `yaml:"set" json:"set"`
	Remove []string          `yaml:"remove" json:"remove"`
}

type BodyReplacement struct {
	// Replace is immutable UTF-8 configuration data, never a reader of traffic.
	// A non-nil BodyReplacement with an empty Replace means replace with empty.
	Replace     string `yaml:"replace" json:"replace"`
	ContentType string `yaml:"content-type" json:"content-type"`
}

type RequestAction struct {
	URL     string           `yaml:"url" json:"url"`
	Method  string           `yaml:"method" json:"method"`
	Headers HeaderAction     `yaml:"headers" json:"headers"`
	Body    *BodyReplacement `yaml:"body" json:"body"`
}

type ResponseAction struct {
	Status  int              `yaml:"status" json:"status"`
	Headers HeaderAction     `yaml:"headers" json:"headers"`
	Body    *BodyReplacement `yaml:"body" json:"body"`
}

type Redirect struct {
	Status   int    `yaml:"status" json:"status"`
	Location string `yaml:"location" json:"location"`
}

type LocalResponse struct {
	Status  int               `yaml:"status" json:"status"`
	Headers map[string]string `yaml:"headers" json:"headers"`
	Body    string            `yaml:"body" json:"body"`
}

type RequestView struct {
	Method  string
	URL     url.URL
	Headers HeaderMap
}

type ResponseView struct {
	StatusCode int
	Headers    HeaderMap
}

type Decision uint8

const (
	Continue Decision = iota
	RedirectResponse
	LocalResponseDecision
)

// TerminalResponse ends request rule execution. The adapter must not dial an
// upstream or run the response pipeline for this decision. For HEAD the adapter
// must suppress transmission of Body while retaining representation metadata.
type TerminalResponse struct {
	Decision   Decision
	StatusCode int
	Headers    HeaderMap
	Body       string
}

// Results borrow input Headers when unchanged. Changed headers are owned by the
// result. Body and Terminal values are owned by each invocation, not Snapshot.
// With Terminal set, Request is the original input and Body is nil. Earlier
// changes only affect matching; Terminal is the sole action to consume.
type RequestResult struct {
	Request  RequestView
	Changed  bool
	Body     *BodyReplacement
	Terminal *TerminalResponse
}

// SuppressBody describes body suppression for the request view and final status.
// Protocol adapters reconcile it with the original client method when a rewrite
// changes HEAD semantics, and manage framing independently of Changed. For
// HEAD/304, replacement content can describe metadata without being transmitted.
type ResponseResult struct {
	SuppressBody bool
	Response     ResponseView
	Changed      bool
	// ContentTypeModified means the final matching Header action changed or
	// removed Content-Type after the latest Body action.
	ContentTypeModified bool
	Body                *BodyReplacement
}

// Separate interfaces let future HTTP/2 adapters and script hooks participate
// without exposing net/http objects or sharing stream-local mutable state.
type RequestPipeline interface {
	ApplyRequest(context.Context, RequestView) (RequestResult, error)
}
type ResponsePipeline interface {
	ApplyResponse(context.Context, RequestView, ResponseView) (ResponseResult, error)
}
