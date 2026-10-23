package config

import (
	"fmt"
	"reflect"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/gojaprocessor"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
	yaml "go.yaml.in/yaml/v3"
)

// RawGoja configures the opt-in production Goja Processor. Body access stays
// streaming unless a phase explicitly requests full-buffered.
type RawGoja struct {
	Enable                   bool   `yaml:"enable" json:"enable"`
	ID                       string `yaml:"id" json:"id"`
	Source                   string `yaml:"source" json:"source"`
	Request                  bool   `yaml:"request" json:"request"`
	Response                 bool   `yaml:"response" json:"response"`
	RequestBody              string `yaml:"request-body" json:"request-body"`
	RequestMaxBodyBytes      int64  `yaml:"request-max-body-bytes" json:"request-max-body-bytes"`
	ResponseBody             string `yaml:"response-body" json:"response-body"`
	ResponseMaxBodyBytes     int64  `yaml:"response-max-body-bytes" json:"response-max-body-bytes"`
	MaxOutputBytes           int64  `yaml:"max-output-bytes" json:"max-output-bytes"`
	MaxOutputBodyBytes       int64  `yaml:"max-output-body-bytes" json:"max-output-body-bytes"`
	Capacity                 int    `yaml:"capacity" json:"capacity"`
	MaxSourceBytes           int    `yaml:"max-source-bytes" json:"max-source-bytes"`
	MaxInputBytes            int    `yaml:"max-input-bytes" json:"max-input-bytes"`
	MaxSerializedOutputBytes int    `yaml:"max-serialized-output-bytes" json:"max-serialized-output-bytes"`
	ExecutionTimeout         int    `yaml:"execution-timeout" json:"execution-timeout"`
	TotalTimeout             int    `yaml:"total-timeout" json:"total-timeout"`
}

func (raw *RawGoja) UnmarshalYAML(node *yaml.Node) error {
	if err := checkStrictFields(node, reflect.TypeOf(RawGoja{}), make(map[rewriteFieldVisit]uint8), "mitm.goja-processor"); err != nil {
		return err
	}
	type rawGojaAlias RawGoja
	var decoded rawGojaAlias
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*raw = RawGoja(decoded)
	return nil
}

func parseMITMGoja(raw RawGoja) (func() ([]pipeline.Entry, error), error) {
	if !raw.Enable {
		return nil, nil
	}
	requestBody, err := gojaprocessor.ParseBodyNeed(raw.RequestBody)
	if err != nil {
		return nil, fmt.Errorf("request-body %w", err)
	}
	responseBody, err := gojaprocessor.ParseBodyNeed(raw.ResponseBody)
	if err != nil {
		return nil, fmt.Errorf("response-body %w", err)
	}
	executionTimeout, err := parseGojaTimeout("execution-timeout", raw.ExecutionTimeout)
	if err != nil {
		return nil, err
	}
	totalTimeout, err := parseGojaTimeout("total-timeout", raw.TotalTimeout)
	if err != nil {
		return nil, err
	}
	factory, err := gojaprocessor.NewFactory(gojaprocessor.Config{
		ID:                       raw.ID,
		Source:                   raw.Source,
		Request:                  raw.Request,
		Response:                 raw.Response,
		RequestBody:              requestBody,
		RequestMaxBodyBytes:      raw.RequestMaxBodyBytes,
		ResponseBody:             responseBody,
		ResponseMaxBodyBytes:     raw.ResponseMaxBodyBytes,
		MaxOutputBytes:           raw.MaxOutputBytes,
		MaxOutputBodyBytes:       raw.MaxOutputBodyBytes,
		Capacity:                 raw.Capacity,
		MaxSourceBytes:           raw.MaxSourceBytes,
		MaxInputBytes:            raw.MaxInputBytes,
		MaxSerializedOutputBytes: raw.MaxSerializedOutputBytes,
		ExecutionTimeout:         executionTimeout,
		TotalTimeout:             totalTimeout,
	})
	if err != nil {
		return nil, err
	}
	return func() ([]pipeline.Entry, error) {
		backend, err := factory.Build()
		if err != nil {
			return nil, err
		}
		return []pipeline.Entry{{Class: pipeline.Script, Priority: 0, Processor: backend}}, nil
	}, nil
}

func parseGojaTimeout(name string, seconds int) (time.Duration, error) {
	if seconds < 0 || seconds > 120 {
		return 0, fmt.Errorf("%s must be between 0 and 120 seconds", name)
	}
	return time.Duration(seconds) * time.Second, nil
}
