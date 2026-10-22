package mitm

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
	"github.com/stretchr/testify/require"
)

type boundaryProcessor struct {
	entered, release           chan struct{}
	drainEntered, drainRelease chan struct{}
	closes                     atomic.Int32
	closeErr                   error
}

func (*boundaryProcessor) Describe() processor.Descriptor {
	return processor.Descriptor{ID: "boundary", Backend: "test", ContractVersion: 1, Request: true}
}
func (*boundaryProcessor) Start(context.Context, model.Input, ...io.Closer) (*processor.Invocation, error) {
	return nil, errors.New("not executed")
}
func (p *boundaryProcessor) Close() error {
	p.closes.Add(1)
	if p.entered != nil {
		close(p.entered)
		<-p.release
	}
	return p.closeErr
}
func (p *boundaryProcessor) WaitClosed(ctx context.Context) error {
	if p.drainEntered != nil {
		close(p.drainEntered)
		select {
		case <-p.drainRelease:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return nil
}
func TestManagerBlockedRetirementAllowsBindAndThirdPublication(t *testing.T) {
	p := &boundaryProcessor{entered: make(chan struct{}), release: make(chan struct{})}
	m := NewManager(Config{Enabled: true, Ports: []uint16{443}, ProcessorFactory: func() ([]pipeline.Entry, error) { return []pipeline.Entry{{Class: pipeline.Script, Processor: p}}, nil }})
	first := m.Generation()
	updated := make(chan error, 1)
	go func() { updated <- m.Update(Config{Enabled: true, Ports: []uint16{443}}) }()
	<-p.entered
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bound := make(chan *Connection, 1)
	go func() { bound <- m.Bind(443) }()
	select {
	case c := <-bound:
		require.NotNil(t, c)
		c.Close()
	case <-ctx.Done():
		t.Fatal("Bind blocked by old Close")
	}
	require.Equal(t, generation.Retiring, first.State())
	_, e := first.Bind()
	require.Error(t, e)
	third := make(chan error, 1)
	go func() { third <- m.Update(Config{Enabled: true, Ports: []uint16{443}}) }()
	select {
	case e := <-third:
		require.NoError(t, e)
	case <-ctx.Done():
		t.Fatal("third publication blocked")
	}
	close(p.release)
	require.NoError(t, <-updated)
	require.NoError(t, first.WaitClosed(ctx))
	require.EqualValues(t, 1, p.closes.Load())
	m.Close()
}

func TestCandidateFailureCleanupOwnership(t *testing.T) {
	for _, mode := range []string{"normal", "blocked-close", "blocked-wait", "close-error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			pool := generation.NewCleanupPool(4)
			m := NewManager(Config{Enabled: true, Ports: []uint16{443}})
			active := m.Generation()
			defer m.Close()
			backend := &boundaryProcessor{}
			if mode == "blocked-wait" {
				backend.drainEntered = make(chan struct{})
				backend.drainRelease = make(chan struct{})
			}
			if mode == "blocked-close" || mode == "canceled" {
				backend.entered = make(chan struct{})
				backend.release = make(chan struct{})
			}
			sentinel := errors.New("close failure")
			if mode == "close-error" {
				backend.closeErr = sentinel
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			factoryFailure := errors.New("second processor initialization failed")
			returned := make(chan error, 1)
			go func() {
				returned <- m.UpdateContext(ctx, Config{Enabled: true, Ports: []uint16{443}, cleanupPool: pool, ProcessorFactory: func() ([]pipeline.Entry, error) {
					if mode == "canceled" {
						cancel()
					}
					return []pipeline.Entry{{Class: pipeline.Script, Processor: backend}}, factoryFailure
				}})
			}()
			if backend.entered != nil {
				<-backend.entered
			}
			if backend.drainEntered != nil {
				<-backend.drainEntered
			}
			watchdog, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			var err error
			select {
			case err = <-returned:
			case <-watchdog.Done():
				t.Fatal("candidate cleanup wait unbounded")
			}
			require.ErrorIs(t, err, factoryFailure)
			var owner *generation.BuildError
			require.ErrorAs(t, err, &owner)
			require.Same(t, active, m.Generation())
			c := m.Bind(443)
			require.NotNil(t, c)
			c.Close()
			if mode == "blocked-close" || mode == "canceled" || mode == "blocked-wait" {
				if mode != "canceled" {
					require.ErrorIs(t, err, context.DeadlineExceeded)
				} else {
					require.ErrorIs(t, err, context.Canceled)
				}
				require.Equal(t, generation.Retiring, owner.Pending.State())
				require.Equal(t, 1, pool.Outstanding())
				// A later update finishes while the failed resource remains owned/blocked.
				require.NoError(t, m.Update(Config{Enabled: true, Ports: []uint16{443}}))
				if backend.release != nil {
					close(backend.release)
				}
				if backend.drainRelease != nil {
					close(backend.drainRelease)
				}
			}
			cleanupErr := owner.Pending.WaitClosed(watchdog)
			if mode == "close-error" {
				require.ErrorIs(t, err, sentinel)
				require.ErrorIs(t, cleanupErr, sentinel)
			} else {
				require.NoError(t, cleanupErr)
			}
			owner.Pending.Close()
			owner.Pending.Retire()
			require.EqualValues(t, 1, backend.closes.Load())
			require.NoError(t, pool.WaitIdle(watchdog))
			require.Zero(t, pool.Outstanding())
		})
	}
}

func TestCandidateAdmissionPrecedesFactory(t *testing.T) {
	pool := generation.NewCleanupPool(1)
	reservation, e := pool.Reserve()
	require.NoError(t, e)
	defer reservation.Release()
	m := NewManager(Config{Enabled: true, Ports: []uint16{443}})
	defer m.Close()
	old := m.Generation()
	var calls atomic.Int32
	e = m.Update(Config{Enabled: true, Ports: []uint16{443}, cleanupPool: pool, ProcessorFactory: func() ([]pipeline.Entry, error) { calls.Add(1); return nil, nil }})
	require.ErrorIs(t, e, generation.ErrCleanupCapacity)
	require.Zero(t, calls.Load())
	require.Same(t, old, m.Generation())
}

func TestCandidateCanceledAfterSuccessfulInitialization(t *testing.T) {
	pool := generation.NewCleanupPool(2)
	m := NewManager(Config{Enabled: true, Ports: []uint16{443}})
	defer m.Close()
	active := m.Generation()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &boundaryProcessor{}
	err := m.UpdateContext(ctx, Config{Enabled: true, Ports: []uint16{443}, cleanupPool: pool, ProcessorFactory: func() ([]pipeline.Entry, error) {
		cancel()
		return []pipeline.Entry{{Class: pipeline.Script, Processor: backend}}, nil
	}})
	require.ErrorIs(t, err, context.Canceled)
	var failed *generation.BuildError
	require.ErrorAs(t, err, &failed)
	watchdog, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	require.NoError(t, failed.Pending.WaitClosed(watchdog))
	require.NoError(t, pool.WaitIdle(watchdog))
	require.Same(t, active, m.Generation())
	require.EqualValues(t, 1, backend.closes.Load())
}
