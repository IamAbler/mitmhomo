package executor_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/component/mitm/httphook"
	"github.com/metacubex/mihomo/component/mitm/processing/generation"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/pipeline"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestM48RealConfigPublication(t *testing.T) {
	if os.Getenv("M48_CONFIG_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestM48RealConfigPublication$", "-test.v", "-test.timeout=40s")
		cmd.Env = append(os.Environ(), "M48_CONFIG_CHILD=1")
		out, e := cmd.CombinedOutput()
		require.NoError(t, e, "%s", out)
		t.Log(string(out))
		return
	}
	home := t.TempDir()
	C.SetHomeDir(home)
	roots := m35ExecutorCA(t, home)
	lifecycle, _ := processor.NewLifecycle(1)
	async := &m48AsyncProcessor{l: lifecycle, started: make(chan *processor.Invocation, 1), finish: make(chan *processor.Completion, 1)}
	async.closeEntered = make(chan struct{})
	async.closeRelease = make(chan struct{})
	var releaseOld sync.Once
	defer releaseOld.Do(func() { close(async.closeRelease) })
	yaml := func(version string, enabled bool) []byte {
		return []byte(fmt.Sprintf(`mode: direct
log-level: silent
find-process-mode: off
geo-auto-update: false
profile: {store-selected: false}
dns: {enable: false}
tun: {enable: false, auto-route: false, dns-mode: disabled}
ntp: {enable: false}
iptables: {enable: false}
mitm:
  enable: %t
  domains: [localhost]
  ca-cert: ca.pem
  ca-key: ca-key.pem
  rewrite:
    enable: true
    rules:
      - name: local
        local-response:
          status: 200
          body: %s
`, enabled, version))
	}
	apply := func(version string, enabled bool) *generation.Generation {
		cfg, e := config.Parse(yaml(version, enabled))
		require.NoError(t, e)
		if version == "old" {
			cfg.MITM.ProcessorFactory = func() ([]pipeline.Entry, error) {
				return []pipeline.Entry{{Class: pipeline.Script, Processor: async}}, nil
			}
			cfg.MITM.RequestHook = func(request *http.Request) error {
				if request.URL.Path != "/async" {
					return nil
				}
				runner, ok := mitm.ProcessingRunnerFromContext(request.Context())
				if !ok {
					return fmt.Errorf("missing bound pipeline")
				}
				tx, e := m48Transaction(runner.GenerationID())
				if e != nil {
					return e
				}
				defer tx.Close()
				_, e = runner.Run(request.Context(), tx, model.RequestPhase)
				if e == nil {
					return fmt.Errorf("expected canceled invocation")
				}
				return nil
			}
		}
		require.NoError(t, hub.ApplyConfig(cfg))
		return tunnel.MITMGeneration()
	}
	old := apply("old", true)
	require.NotNil(t, old)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type client struct {
		rt   http.RoundTripper
		raw  net.Conn
		done chan struct{}
	}
	clients := []*client{}
	defer func() {
		for _, c := range clients {
			c.raw.Close()
		}
		apply("off", false)
	}()
	start := func(h2 bool) *client {
		server, raw := net.Pipe()
		c := &client{raw: raw, done: make(chan struct{})}
		clients = append(clients, c)
		go func() {
			defer close(c.done)
			tunnel.Tunnel.HandleTCPConn(server, &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443, SrcIP: netip.MustParseAddr("192.0.2.48"), SrcPort: 44800})
		}()
		protocols := []string{"http/1.1"}
		if h2 {
			protocols = []string{"h2"}
		}
		secure := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: protocols, MinVersion: tls.VersionTLS12})
		require.NoError(t, secure.HandshakeContext(ctx))
		if h2 {
			var e error
			c.rt, e = (&http2.Transport{}).NewClientConn(secure)
			require.NoError(t, e)
		} else {
			c.rt = &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return secure, nil }}
		}
		return c
	}
	send := func(c *client, want string) {
		r, e := http.NewRequestWithContext(ctx, "GET", "https://localhost/", nil)
		require.NoError(t, e)
		resp, e := c.rt.RoundTrip(r)
		require.NoError(t, e)
		data, e := io.ReadAll(resp.Body)
		require.NoError(t, e)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, want, string(data))
	}
	h1, h2 := start(false), start(true)
	send(h1, "old")
	send(h2, "old")
	asyncResponse := make(chan error, 1)
	go func() {
		r, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/async", nil)
		resp, e := h2.rt.RoundTrip(r)
		if e == nil {
			_, e = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		asyncResponse <- e
	}()
	invocation := <-async.started
	completion := <-async.finish
	second := apply("second", true)
	invocation.Cancel(context.Canceled)
	require.NoError(t, <-asyncResponse)
	require.Equal(t, generation.Retiring, old.State())
	send(h1, "old")
	send(h2, "old")
	fresh := start(true)
	send(fresh, "second")
	third := apply("third", true)
	send(h2, "old")
	send(fresh, "second")
	newest := start(true)
	send(newest, "third")
	// Parse failure and production candidate failure both leave the active pointer.
	_, e := config.Parse([]byte("mitm: {enable: true, domains: ['bad*domain']}"))
	require.Error(t, e)
	require.Same(t, third, tunnel.MITMGeneration())
	invalid, e := config.Parse(yaml("invalid", true))
	require.NoError(t, e)
	invalid.MITM.CA = nil
	require.Error(t, hub.ApplyConfig(invalid))
	require.Same(t, third, tunnel.MITMGeneration())
	send(newest, "third")
	invalid, e = config.Parse(yaml("invalid-script", true))
	require.NoError(t, e)
	invalid.MITM.ScriptHooks, e = httphook.Compile(httphook.Config{Enable: true, Rules: []httphook.Rule{{Name: "syntax", Phase: httphook.RequestPhase, Source: "function {"}}})
	require.NoError(t, e)
	require.Error(t, hub.ApplyConfig(invalid))
	require.Same(t, third, tunnel.MITMGeneration())
	require.NoError(t, invalid.MITM.ScriptHooks.Close())
	invalid, e = config.Parse(yaml("failed-factory", true))
	require.NoError(t, e)
	partialLife, _ := processor.NewLifecycle(1)
	partial := &m48AsyncProcessor{l: partialLife}
	invalid.MITM.ProcessorFactory = func() ([]pipeline.Entry, error) {
		return []pipeline.Entry{{Class: pipeline.Script, Processor: partial}}, fmt.Errorf("processor initialization failed")
	}
	require.Error(t, hub.ApplyConfig(invalid))
	require.EqualValues(t, 1, partial.closed.Load())
	require.Same(t, third, tunnel.MITMGeneration())
	// A partial backend can violate bounded Close without owning the Apply
	// thread. The failed Generation and its reservation remain explicit owners.
	invalid, e = config.Parse(yaml("blocked-factory", true))
	require.NoError(t, e)
	blockedLife, _ := processor.NewLifecycle(1)
	blocked := &m48AsyncProcessor{l: blockedLife, closeEntered: make(chan struct{}), closeRelease: make(chan struct{})}
	var unblock sync.Once
	defer unblock.Do(func() { close(blocked.closeRelease) })
	invalid.MITM.ProcessorFactory = func() ([]pipeline.Entry, error) {
		return []pipeline.Entry{{Class: pipeline.Script, Processor: blocked}}, fmt.Errorf("partial initialization failed")
	}
	failedApply := make(chan error, 1)
	go func() { failedApply <- hub.ApplyConfig(invalid) }()
	select {
	case <-blocked.closeEntered:
	case <-ctx.Done():
		t.Fatal("partial Close not entered")
	}
	var failedErr error
	select {
	case failedErr = <-failedApply:
	case <-ctx.Done():
		t.Fatal("Apply held by partial Close")
	}
	require.ErrorIs(t, failedErr, context.DeadlineExceeded)
	var pending *generation.BuildError
	require.ErrorAs(t, failedErr, &pending)
	require.Same(t, third, tunnel.MITMGeneration())
	send(newest, "third")
	require.Nil(t, apply("off", false))
	send(h2, "old")
	send(newest, "third")
	fourth := apply("fourth", true)
	send(start(true), "fourth")
	require.NotEqual(t, third.ID(), fourth.ID())
	unblock.Do(func() { close(blocked.closeRelease) })
	require.NoError(t, pending.Pending.WaitClosed(ctx))
	require.EqualValues(t, 1, blocked.closed.Load())
	// Two real ApplyConfig calls serialize the entire Executor mutation path.
	configs := make([]*config.Config, 2)
	for i := range configs {
		configs[i], e = config.Parse(yaml(fmt.Sprintf("parallel%d", i), true))
		require.NoError(t, e)
	}
	gate := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, cfg := range configs {
		wg.Add(1)
		go func(cfg *config.Config) { defer wg.Done(); <-gate; errs <- executor.ApplyConfig(cfg, true) }(cfg)
	}
	close(gate)
	wg.Wait()
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	apply("off", false)
	for _, c := range clients {
		require.NoError(t, c.raw.Close())
		select {
		case <-c.done:
		case <-ctx.Done():
			t.Fatal("connection did not drain")
		}
	}
	for _, g := range []*generation.Generation{old, second, third, fourth} {
		if g == old {
			require.Equal(t, generation.Retiring, g.State())
			require.Equal(t, 1, lifecycle.Active())
			require.Zero(t, async.closed.Load())
			require.True(t, completion.Finish(model.Continue(), nil))
			require.Zero(t, lifecycle.Active())
			select {
			case <-async.closeEntered:
			case <-ctx.Done():
				t.Fatal("retired cleanup not entered")
			}
			require.Equal(t, generation.Retiring, old.State())
			// This full Hub/Executor publication and a new TLS/H2 connection
			// must finish before the retired processor is allowed to close.
			reloaded := apply("while-old-close-blocked", true)
			bound := start(true)
			send(bound, "while-old-close-blocked")
			bound.raw.Close()
			select {
			case <-bound.done:
			case <-ctx.Done():
				t.Fatal("new connection stuck")
			}
			apply("off", false)
			require.NoError(t, reloaded.WaitClosed(ctx))
			releaseOld.Do(func() { close(async.closeRelease) })
		}
		require.NoError(t, g.WaitClosed(ctx))
		if g == old {
			require.EqualValues(t, 1, async.closed.Load())
		}
		require.Equal(t, generation.Closed, g.State())
	}
	t.Log("Parse -> hub.ApplyConfig -> executor.ApplyConfig -> Tunnel; H1/H2 pinned; rollback, disable/re-enable, concurrent ApplyConfig, explicit drain PASS")
}

type m48AsyncProcessor struct {
	closeEntered, closeRelease chan struct{}
	closed                     atomic.Int32
	l                          *processor.Lifecycle
	started                    chan *processor.Invocation
	finish                     chan *processor.Completion
}

func (p *m48AsyncProcessor) Describe() processor.Descriptor {
	return processor.Descriptor{ID: "m48-async", Backend: "test-adapter", ContractVersion: 1, Request: true}
}
func (p *m48AsyncProcessor) Start(ctx context.Context, in model.Input, resources ...io.Closer) (*processor.Invocation, error) {
	i, c, e := p.l.BeginWithResources(ctx, in.Key(), resources...)
	if e == nil {
		p.started <- i
		p.finish <- c
	}
	return i, e
}
func (p *m48AsyncProcessor) Close() error {
	p.closed.Add(1)
	if p.closeEntered != nil {
		close(p.closeEntered)
		<-p.closeRelease
	}
	return p.l.Close()
}
func (p *m48AsyncProcessor) WaitClosed(ctx context.Context) error { return p.l.WaitClosed(ctx) }
func m48Transaction(id model.GenerationID) (*model.Transaction, error) {
	ledger, e := model.NewLedger(-1, nil)
	if e != nil {
		return nil, e
	}
	copy := model.NewCopyLease(ledger)
	defer copy.Close()
	u, e := model.ParseURL(copy, "https://localhost/async", model.MITMHTTPS)
	if e != nil {
		return nil, e
	}
	headers, e := model.NewHeaderBlock(copy, nil)
	if e != nil {
		return nil, e
	}
	trailers, e := model.NewTrailerView(model.TrailerUnavailable, model.HeaderBlock{}, model.HeaderBlock{})
	if e != nil {
		return nil, e
	}
	head := model.RequestHead{Method: "GET", URL: u, Authority: "localhost", Headers: headers, Trailers: trailers}
	broker, e := model.NewBodyBroker(context.Background(), model.BodySource{Owner: model.FrameworkOwned}, ledger)
	if e != nil {
		return nil, e
	}
	return model.NewTransaction(context.Background(), model.TransactionOptions{ID: "real-config-async", Generation: id, Connection: model.ConnectionView{ID: "real-h2", StreamID: "async"}, OriginalIngress: head, Request: head, RequestBody: model.NewBodySlot(broker), Ledger: ledger})
}
