// Package gojaprocessor adapts Goja to the HTTP Processing Framework.
//
// A Processor owns one generation-scoped jsruntime.Runtime and immutable
// compiled program. Each invocation is admitted through processor.Lifecycle
// and jsruntime executes it in a fresh Goja VM. JavaScript only receives a
// bounded JSON snapshot and can return a validated model.DoneResult; it never
// receives a Transaction or any Go-owned mutable object.
package gojaprocessor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/mitm/jsruntime"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

const (
	defaultCapacity            = 32
	defaultSourceLimit         = 256 << 10
	maxSourceLimit             = 1 << 20
	defaultInputLimit          = 2 << 20
	defaultSerializedOutput    = 2 << 20
	maxJSONLimit               = 16 << 20
	defaultExecutionTimeout    = time.Second
	maxExecutionTimeout        = 120 * time.Second
	defaultProcessorOutputSize = model.DefaultProcessorOutputBytes
)

const apiVersion = 1

const entryPrefix = `(function(input) {
"use strict";
`

const entrySuffix = `
if (typeof process !== "function") {
	throw new Error("Goja processor must define process(input)");
}
return process(input);
})(input)`

// Config is immutable processor-generation configuration. Source is compiled
// by New, before the processor is published in a Generation.
type Config struct {
	ID       string
	Source   string
	Request  bool
	Response bool

	RequestBody          model.BodyNeed
	RequestMaxBodyBytes  int64
	ResponseBody         model.BodyNeed
	ResponseMaxBodyBytes int64

	// MaxOutputBytes is the immutable DoneResult allocation cap. The Pipeline
	// also applies its Transaction-specific output limit before commit.
	MaxOutputBytes int64
	// MaxOutputBodyBytes caps decoded body replacements and synthetic bodies.
	MaxOutputBodyBytes int64

	// Capacity is a processor-local cap. The Pipeline's shared InvocationPool
	// remains an independent framework-wide admission limit.
	Capacity int

	MaxSourceBytes           int
	MaxInputBytes            int
	MaxSerializedOutputBytes int
	ExecutionTimeout         time.Duration
	TotalTimeout             time.Duration
}

// Processor is a generation-owned Goja backend. Close interrupts active
// invocations and rejects new ones. WaitClosed is the explicit execution
// drain; it drops the retained Program only after all VM executions finish.
type Processor struct {
	mu         sync.Mutex
	config     Config
	descriptor processor.Descriptor
	runtime    *jsruntime.Runtime
	program    *jsruntime.CompiledScript
	lifecycle  *processor.Lifecycle
	closeOnce  sync.Once
	closeErr   error
}

// Factory holds immutable script configuration and builds a fresh Processor
// for each Generation. Every Build creates a new runtime and generation-scoped
// one-entry Program cache, so hot updates cannot replace the old generation's
// script.
type Factory struct{ config Config }

func NewFactory(config Config) (*Factory, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Factory{config: normalized}, nil
}

// Build compiles a new immutable Program and returns a generation-owned
// Processor. Syntax and compile errors are exposed here before publication.
func (f *Factory) Build() (*Processor, error) {
	if f == nil {
		return nil, configFailure("", "nil Goja Processor Factory")
	}
	return New(f.config)
}

// New validates configuration and compiles the wrapped process(input) program.
// A syntax or compilation error is returned before this processor can be
// published. The compile cache has one entry and is owned by this Processor.
func New(config Config) (*Processor, error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	life, err := processor.NewProcessorLifecycle(config.ID, config.Capacity)
	if err != nil {
		return nil, err
	}
	engineConfig := jsruntime.Config{
		MaxSourceBytes:      config.MaxSourceBytes + len(entryPrefix) + len(entrySuffix),
		MaxInputBytes:       config.MaxInputBytes,
		MaxOutputBytes:      config.MaxSerializedOutputBytes,
		MaxConcurrent:       config.Capacity,
		ExecutionTimeout:    config.ExecutionTimeout,
		CompileCacheEntries: 1,
	}
	runtime, err := jsruntime.New(engineConfig)
	if err != nil {
		return nil, model.NewProcessingError(model.ProcessingErrorInvalidConfiguration, model.ProcessingOriginProcessor, model.PhaseInvalid, config.ID, "", err)
	}
	program, err := runtime.Compile(entryPrefix + config.Source + entrySuffix)
	if err != nil {
		_ = runtime.Close()
		return nil, compileError(config.ID, err)
	}

	descriptor := processor.Descriptor{
		ID:              config.ID,
		Backend:         "goja",
		ContractVersion: apiVersion,
		Request:         config.Request,
		Response:        config.Response,
		RequestNeeds:    requirements(config.Request, config.RequestBody, config.RequestMaxBodyBytes, config),
		ResponseNeeds:   requirements(config.Response, config.ResponseBody, config.ResponseMaxBodyBytes, config),
	}
	if err := descriptor.Validate(); err != nil {
		_ = runtime.Close()
		return nil, err
	}
	return &Processor{config: config, descriptor: descriptor, runtime: runtime, program: program, lifecycle: life}, nil
}

func requirements(enabled bool, body model.BodyNeed, maxBodyBytes int64, config Config) processor.Requirements {
	if !enabled {
		return processor.Requirements{}
	}
	return processor.Requirements{
		Body: body, MaxBodyBytes: maxBodyBytes,
		MaxOutputBytes: config.MaxOutputBytes, TotalTimeout: config.TotalTimeout,
		ExecutionTimeout: config.ExecutionTimeout,
	}
}

func normalizeConfig(config Config) (Config, error) {
	invalid := func(message string) (Config, error) {
		return Config{}, model.NewProcessingError(model.ProcessingErrorInvalidConfiguration, model.ProcessingOriginProcessor, model.PhaseInvalid, config.ID, "", fmt.Errorf("%w: %s", model.ErrInvalid, message))
	}
	if config.ID == "" || strings.TrimSpace(config.ID) != config.ID || !config.Request && !config.Response {
		return invalid("ID and at least one supported phase are required")
	}
	if len(config.Source) == 0 {
		return invalid("Source is empty")
	}
	if config.MaxSourceBytes == 0 {
		config.MaxSourceBytes = defaultSourceLimit
	}
	if config.MaxSourceBytes <= 0 || config.MaxSourceBytes > maxSourceLimit || len(config.Source) > config.MaxSourceBytes {
		return invalid("Source exceeds the configured source limit")
	}
	if config.MaxInputBytes == 0 {
		config.MaxInputBytes = defaultInputLimit
	}
	if config.MaxInputBytes <= 0 || config.MaxInputBytes > maxJSONLimit {
		return invalid("MaxInputBytes is outside the supported bounded range")
	}
	if config.MaxSerializedOutputBytes == 0 {
		config.MaxSerializedOutputBytes = defaultSerializedOutput
	}
	if config.MaxSerializedOutputBytes <= 0 || config.MaxSerializedOutputBytes > maxJSONLimit {
		return invalid("MaxSerializedOutputBytes is outside the supported bounded range")
	}
	if config.MaxOutputBytes == 0 {
		config.MaxOutputBytes = defaultProcessorOutputSize
	}
	if config.MaxOutputBytes <= 0 || config.MaxOutputBytes > model.DefaultProcessorOutputBytes {
		return invalid("MaxOutputBytes must be within the framework processor output limit")
	}
	if config.MaxOutputBodyBytes == 0 {
		config.MaxOutputBodyBytes = config.MaxOutputBytes
	}
	if config.MaxOutputBodyBytes < 0 || config.MaxOutputBodyBytes > config.MaxOutputBytes {
		return invalid("MaxOutputBodyBytes must be non-negative and no greater than MaxOutputBytes")
	}
	if config.Capacity == 0 {
		config.Capacity = defaultCapacity
	}
	if config.Capacity < 1 || config.Capacity > processor.DefaultInvocationCapacity {
		return invalid("Capacity is outside the bounded InvocationPool range")
	}
	if config.ExecutionTimeout == 0 {
		config.ExecutionTimeout = defaultExecutionTimeout
	}
	if config.ExecutionTimeout < 0 || config.ExecutionTimeout > maxExecutionTimeout || config.TotalTimeout < 0 {
		return invalid("execution timeout must be positive and at most 120 seconds; total timeout cannot be negative")
	}
	if config.TotalTimeout > maxExecutionTimeout {
		return invalid("TotalTimeout cannot exceed 120 seconds")
	}
	if err := normalizeBodyNeed(config.Request, &config.RequestBody, &config.RequestMaxBodyBytes); err != nil {
		return invalid("invalid Request body requirement")
	}
	if err := normalizeBodyNeed(config.Response, &config.ResponseBody, &config.ResponseMaxBodyBytes); err != nil {
		return invalid("invalid Response body requirement")
	}
	return config, nil
}

func normalizeBodyNeed(enabled bool, need *model.BodyNeed, limit *int64) error {
	if *need > model.FullBuffered || *limit < 0 {
		return model.ErrInvalid
	}
	if !enabled {
		if *need != model.None || *limit != 0 {
			return model.ErrInvalid
		}
		return nil
	}
	if *need == model.None {
		if *limit != 0 {
			return model.ErrInvalid
		}
		return nil
	}
	if *limit == 0 {
		*limit = model.DefaultBodyBufferBytes
	}
	if *limit > model.DefaultBodyBufferBytes {
		return model.ErrInvalid
	}
	return nil
}

func compileError(id string, err error) error {
	kind := model.ProcessingErrorCompile
	if errors.Is(err, jsruntime.ErrResourceLimit) {
		kind = model.ProcessingErrorResourceLimit
	} else if errors.Is(err, jsruntime.ErrInvalidConfig) {
		kind = model.ProcessingErrorInvalidConfiguration
	}
	return model.NewProcessingError(kind, model.ProcessingOriginProcessor, model.PhaseInvalid, id, "", err)
}

// Describe returns the immutable capability and resource snapshot.
func (p *Processor) Describe() processor.Descriptor {
	if p == nil {
		return processor.Descriptor{}
	}
	return p.descriptor.Clone()
}

// Start performs admission and ownership transfer synchronously, then starts
// one bounded goroutine for the admitted VM execution. Resources remain owned
// by the Invocation until Finish observes actual Goja exit.
func (p *Processor) Start(ctx context.Context, input model.Input, resources ...io.Closer) (*processor.Invocation, error) {
	if p == nil {
		return nil, model.NewProcessingError(model.ProcessingErrorClosed, model.ProcessingOriginProcessor, model.PhaseInvalid, "", "", model.ErrClosed)
	}
	key := input.Key()
	if key.Phase == model.RequestPhase && !p.descriptor.Request || key.Phase == model.ResponsePhase && !p.descriptor.Response || key.Phase != model.RequestPhase && key.Phase != model.ResponsePhase {
		return nil, model.NewProcessingError(model.ProcessingErrorInvalidInput, model.ProcessingOriginProcessor, key.Phase, p.descriptor.ID, key.Invocation, model.ErrInvalid)
	}
	if len(resources) > 16 {
		return nil, model.NewProcessingError(model.ProcessingErrorResourceLimit, model.ProcessingOriginProcessor, key.Phase, p.descriptor.ID, key.Invocation, model.ErrResourceLimit)
	}
	invocation, completion, err := p.lifecycle.BeginWithResources(ctx, key, resources...)
	if err != nil {
		var processingErr *model.ProcessingError
		if errors.As(err, &processingErr) && processingErr.Kind == model.ProcessingErrorResourceLimit {
			return nil, model.NewProcessingError(model.ProcessingErrorCapacityExhausted, model.ProcessingOriginProcessor, key.Phase, p.descriptor.ID, key.Invocation, errors.Join(model.ErrCapacityExhausted, err))
		}
		return nil, err
	}
	p.mu.Lock()
	program := p.program
	p.mu.Unlock()
	if program == nil {
		completion.Finish(model.DoneResult{}, model.NewProcessingError(model.ProcessingErrorClosed, model.ProcessingOriginProcessor, key.Phase, p.descriptor.ID, key.Invocation, model.ErrClosed))
		return invocation, nil
	}
	go p.execute(invocation.Context(), input, program, completion)
	return invocation, nil
}

func (p *Processor) execute(ctx context.Context, input model.Input, program *jsruntime.CompiledScript, completion *processor.Completion) {
	result, err := p.run(ctx, input, program)
	completion.Finish(result, err)
}

func (p *Processor) run(ctx context.Context, input model.Input, program *jsruntime.CompiledScript) (model.DoneResult, error) {
	jsInput, err := makeInput(input, p.requirements(input.Key().Phase))
	if err != nil {
		return model.DoneResult{}, inputError(input, p.descriptor.ID, err)
	}
	if size, sizeErr := boundedJSONSize(jsInput, p.config.MaxInputBytes); sizeErr != nil || size > p.config.MaxInputBytes {
		if sizeErr == nil {
			sizeErr = fmt.Errorf("serialized JavaScript input exceeds %d bytes", p.config.MaxInputBytes)
		}
		return model.DoneResult{}, processingFailure(model.ProcessingErrorResourceLimit, input, p.descriptor.ID, sizeErr)
	}
	output, err := p.runtime.RunCompiled(ctx, program, jsInput)
	if err != nil {
		return model.DoneResult{}, runtimeError(input, p.descriptor.ID, err)
	}
	result, err := decodeResult(input, output, p.config.MaxOutputBodyBytes)
	if err != nil {
		if outputLimitError(err) {
			return model.DoneResult{}, processingFailure(model.ProcessingErrorOutputLimitExceeded, input, p.descriptor.ID, err)
		}
		return model.DoneResult{}, invalidOutput(input, p.descriptor.ID, err)
	}
	if err = result.ValidateForInput(input); err != nil {
		_ = result.Release()
		return model.DoneResult{}, invalidOutput(input, p.descriptor.ID, err)
	}
	if result.AllocatedBytes() > p.config.MaxOutputBytes {
		_ = result.Release()
		return model.DoneResult{}, processingFailure(model.ProcessingErrorOutputLimitExceeded, input, p.descriptor.ID, model.ErrOutputLimit)
	}
	return result, nil
}

func (p *Processor) requirements(phase model.Phase) processor.Requirements {
	if phase == model.ResponsePhase {
		return p.descriptor.ResponseNeeds
	}
	return p.descriptor.RequestNeeds
}

// Close rejects future invocations and interrupts active Goja executions. It
// does not wait for the VMs or execution-resource cleanup to finish.
func (p *Processor) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.closeErr = errors.Join(p.lifecycle.Close(), p.runtime.Close())
	})
	return p.closeErr
}

// WaitClosed waits for real execution completion. On timeout it retains the
// immutable Program because an active VM may still reference it.
func (p *Processor) WaitClosed(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if err := p.lifecycle.WaitClosed(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	p.program = nil
	p.mu.Unlock()
	return nil
}
