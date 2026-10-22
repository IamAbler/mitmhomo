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
	entered, release chan struct{}
	closes           atomic.Int32
	closeErr         error
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
func (*boundaryProcessor) WaitClosed(context.Context) error { return nil }
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
