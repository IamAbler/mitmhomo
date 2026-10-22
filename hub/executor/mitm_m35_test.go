package executor_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "go.yaml.in/yaml/v3"
	"golang.org/x/net/http2"
)

// File -> public ParseWithPath -> full ApplyConfig -> public Tunnel TCP entry.
// No Manager.Update, UpdateRules, substitute dispatcher or fake Native dialer.
// Device/DNS/iptables listeners stay disabled: this test cannot mutate system
// routes or claim to exercise a kernel TUN device.
func TestM35ExecutorReloadActiveMITM(t *testing.T) {
	if os.Getenv("M35_EXECUTOR_CHILD") != "1" {
		m35ExecutorChild(t, "")
		return
	}
	fault := os.Getenv("M35_EXECUTOR_FAULT")
	inject := func(stage string) {
		if fault == stage {
			t.Fatalf("injected executor failure at %s", stage)
		}
	}
	requestCtx, cancelRequests := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelRequests()
	var requests sync.WaitGroup
	home := t.TempDir()
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(home)
	defer C.SetHomeDir(oldHome)
	roots := m35ExecutorCA(t, home)
	var accepts, connects, active atomic.Int32
	var relays sync.WaitGroup
	held, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, 2, r.ProtoMajor)
		if r.URL.Path == "/hold-old" {
			close(held)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, r.URL.Path)
	}))
	upstream.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			accepts.Add(1)
			active.Add(1)
		}
		if s == http.StateClosed {
			active.Add(-1)
		}
	}
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	target := upstream.Listener.Addr().String()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relays.Add(1)
		defer relays.Done()
		if r.Method != "CONNECT" || r.Host != target {
			http.Error(w, "wrong CONNECT", 400)
			return
		}
		connects.Add(1)
		dialCtx, stopDial := context.WithTimeout(r.Context(), 3*time.Second)
		defer stopDial()
		remote, e := (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
		if e != nil {
			http.Error(w, "dial failed", 502)
			return
		}
		defer remote.Close()
		client, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer client.Close()
		rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		rw.Flush()
		done := make(chan struct{})
		go func() { io.Copy(remote, rw); remote.Close(); close(done) }()
		io.Copy(client, remote)
		client.Close()
		<-done
	}))
	defer proxy.Close()
	proxyHost, proxyPort, _ := net.SplitHostPort(proxy.Listener.Addr().String())
	port, _ := strconv.Atoi(proxyPort)
	apply := func(version, route string) {
		raw := map[string]any{
			"mode": "rule", "log-level": "silent", "find-process-mode": "off", "geo-auto-update": false,
			"profile": map[string]any{"store-selected": false}, "dns": map[string]any{"enable": false},
			"tun": map[string]any{"enable": false, "auto-route": false, "dns-mode": "disabled"}, "ntp": map[string]any{"enable": false}, "iptables": map[string]any{"enable": false},
			"tls":     map[string]any{"custom-certifactes": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))}},
			"proxies": []any{map[string]any{"name": "ACCEPT_PROXY", "type": "http", "server": proxyHost, "port": port}},
			"rules":   []string{"MATCH," + route},
			"mitm": map[string]any{"enable": true, "domains": []string{"localhost"}, "ports": []string{"443"}, "ca-cert": "ca.pem", "ca-key": "ca-key.pem", "request-timeout": 10, "rewrite": map[string]any{"enable": true, "rules": []any{
				map[string]any{"name": "hold", "match": map[string]any{"path": "/hold"}, "request": map[string]any{"url": upstream.URL + "/hold-" + version}},
				map[string]any{"name": "ordinary", "match": map[string]any{"path": "/"}, "request": map[string]any{"url": upstream.URL + "/" + version}},
				map[string]any{"name": "version", "response": map[string]any{"headers": map[string]any{"set": map[string]string{"X-Config": version}}}},
			}}},
		}
		data, e := yaml.Marshal(raw)
		require.NoError(t, e)
		path := filepath.Join(home, "config.yaml")
		require.NoError(t, os.WriteFile(path, data, 0600))
		cfg, e := executor.ParseWithPath(path)
		require.NoError(t, e)
		require.False(t, cfg.General.Tun.Enable)
		require.False(t, cfg.IPTables.Enable)
		require.False(t, cfg.DNS.Enable)
		require.Equal(t, "disabled", cfg.General.Tun.DNSMode)
		executor.ApplyConfig(cfg, true)
	}
	// Always close connections before servers/config cleanup, including failures.
	var closeFns []func()
	defer func() {
		releaseOnce.Do(func() { close(release) })
		cancelRequests()
		for _, closeConn := range closeFns {
			closeConn()
		}
		requestsDone := make(chan struct{})
		go func() { requests.Wait(); close(requestsDone) }()
		select {
		case <-requestsDone:
		case <-time.After(3 * time.Second):
			t.Error("request workers retained during cleanup")
			return
		}
		proxy.Close()
		relaysDone := make(chan struct{})
		go func() { relays.Wait(); close(relaysDone) }()
		select {
		case <-relaysDone:
		case <-time.After(3 * time.Second):
			t.Error("CONNECT relays retained during cleanup")
			return
		}
		cfg, e := executor.ParseWithBytes([]byte("mode: direct\nlog-level: silent\nprofile: {store-selected: false}\n"))
		if e != nil {
			t.Errorf("cleanup config parse: %v", e)
			return
		}
		executor.ApplyConfig(cfg, true)
		if !assert.Eventually(t, func() bool {
			found := false
			statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
				src := tracker.Info().Metadata.SrcPort
				found = found || src >= 43501 && src <= 43503
				return !found
			})
			return !found && active.Load() == 0
		}, 3*time.Second, time.Millisecond) {
			return
		}
		if !assert.Equal(t, tunnel.Direct, tunnel.Mode()) {
			return
		}
		t.Log("M35_EXECUTOR_CLEANUP_OK")
	}()
	start := func(src uint16) *http2.ClientConn {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			tunnel.Tunnel.HandleTCPConn(server, &C.Metadata{NetWork: C.TCP, Type: C.TUNNEL, Host: "localhost", DstPort: 443, SrcIP: netip.MustParseAddr("192.0.2.35"), SrcPort: src})
		}()
		var cc *http2.ClientConn
		var once sync.Once
		closeFns = append(closeFns, func() {
			once.Do(func() {
				client.Close()
				server.Close()
				if cc != nil {
					cc.Close()
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("Tunnel TCP entry retained")
				}
			})
		})
		secure := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
		ctx, cancel := context.WithTimeout(requestCtx, 3*time.Second)
		defer cancel()
		require.NoError(t, secure.HandshakeContext(ctx))
		inject("setup") // MITM has claimed TLS; fail before H2 initialization.
		var e error
		cc, e = (&http2.Transport{StrictMaxConcurrentStreams: true}).NewClientConn(secure)
		require.NoError(t, e)
		return cc
	}
	send := func(cc *http2.ClientConn, n int, want string) {
		results := make(chan error, n)
		for i := 0; i < n; i++ {
			requests.Add(1)
			go func() {
				defer requests.Done()
				req, _ := http.NewRequestWithContext(requestCtx, "POST", "https://localhost/", strings.NewReader("payload"))
				res, e := cc.RoundTrip(req)
				if e == nil {
					b, readErr := io.ReadAll(res.Body)
					res.Body.Close()
					e = readErr
					if e == nil && (string(b) != "/"+want || res.Header.Get("X-Config") != want) {
						e = fmt.Errorf("snapshot mismatch: %s %s", b, res.Header.Get("X-Config"))
					}
				}
				results <- e
			}()
		}
		completed, failed := 0, 0
		for completed < n {
			select {
			case err := <-results:
				completed++
				if err != nil {
					failed++
					t.Errorf("request failed: %v", err)
				}
			case <-requestCtx.Done():
				cancelRequests()
				for _, closeConn := range closeFns {
					closeConn()
				}
				t.Fatalf("executor batch timeout: completed=%d failed=%d unfinished=%d: %v", completed, failed, n-completed, requestCtx.Err())
			}
		}
		require.Zero(t, failed)
	}
	apply("old", "DIRECT")
	old := start(43501)
	send(old, 10, "old")
	holdDone := make(chan error, 1)
	requests.Add(1)
	go func() {
		defer requests.Done()
		req, _ := http.NewRequestWithContext(requestCtx, "GET", "https://localhost/hold", nil)
		res, e := old.RoundTrip(req)
		if e == nil {
			b, readErr := io.ReadAll(res.Body)
			res.Body.Close()
			e = readErr
			if string(b) != "/hold-old" || res.Header.Get("X-Config") != "old" {
				e = fmt.Errorf("held stream lost snapshot")
			}
		}
		holdDone <- e
	}()
	select {
	case <-held:
	case <-time.After(3 * time.Second):
		t.Fatal("pre-reload stream not active")
	}
	inject("held")
	// Full reload while an existing stream and its upstream TCP remain alive.
	apply("new", "ACCEPT_PROXY")
	send(old, 10, "old")
	require.Zero(t, connects.Load())
	fresh := start(43502)
	send(fresh, 10, "new")
	require.EqualValues(t, 1, connects.Load())
	inject("proxy")
	releaseOnce.Do(func() { close(release) })
	select {
	case e := <-holdDone:
		require.NoError(t, e)
	case <-time.After(3 * time.Second):
		t.Fatal("reload stalled active stream")
	}
	apply("third", "DIRECT")
	send(old, 10, "old")
	send(fresh, 10, "new")
	third := start(43503)
	send(third, 10, "third")
	require.EqualValues(t, 1, connects.Load())
	require.EqualValues(t, 3, accepts.Load(), "three snapshots, three native TCP/TLS leases")
	for _, closeConn := range closeFns {
		closeConn()
	}
	require.Eventually(t, func() bool {
		found := false
		statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
			src := tracker.Info().Metadata.SrcPort
			found = found || src >= 43501 && src <= 43503
			return !found
		})
		return !found
	}, 3*time.Second, time.Millisecond)
	t.Log("full ApplyConfig reloads=3 downstreams=3 streams=61 upstream_TCP_TLS=3 proxy_CONNECT=1 tracked_connections_after=0; kernel_TUN=not_exercised")
}

func m35ExecutorCA(t *testing.T, home string) *x509.CertPool {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)
	template := &x509.Certificate{SerialNumber: big.NewInt(35), Subject: pkix.Name{CommonName: "M35 test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, e)
	encodedKey, e := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(home, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(home, "ca-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), 0600))
	root, e := x509.ParseCertificate(der)
	require.NoError(t, e)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return roots
}

// Full ApplyConfig mutates process-wide singletons beyond the public getters.
// Run the real integration test in a fresh test process rather than pretend a
// default config restores every prior global (including async resolver workers).
func m35ExecutorChild(t *testing.T, fault string) {
	t.Helper()
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestM35ExecutorReloadActiveMITM$", "-test.v", "-test.timeout=20s")
	command.Env = append(os.Environ(), "M35_EXECUTOR_CHILD=1", "M35_EXECUTOR_FAULT="+fault, "TMPDIR="+root, "TMP="+root, "TEMP="+root)
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	require.NoError(t, ctx.Err(), "executor subprocess timed out: %s", output)
	if fault == "" {
		require.NoError(t, err, "executor subprocess: %s", output)
	} else {
		require.Error(t, err, "injected failure must fail the child")
		require.Contains(t, string(output), "injected executor failure at "+fault)
	}
	require.Contains(t, string(output), "M35_EXECUTOR_CLEANUP_OK", "%s", output)
	require.NotContains(t, string(output), "WARNING: DATA RACE")
	require.NotContains(t, string(output), "retained")
	files, readErr := os.ReadDir(root)
	require.NoError(t, readErr)
	require.Empty(t, files, "child temporary files must be removed even after FailNow")
	t.Logf("executor child fault=%q cleanup_verified=true", fault)
	if fault == "" {
		t.Logf("%s", output)
	}
}

func TestM35ExecutorFailureCleanup(t *testing.T) {
	for _, fault := range []string{"setup", "held", "proxy"} {
		t.Run(fault, func(t *testing.T) { m35ExecutorChild(t, fault) })
	}
}
