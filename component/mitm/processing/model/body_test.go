package model

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countedBody struct {
	reader        io.Reader
	reads, closes atomic.Int32
	bytes         atomic.Int64
	closeErr      error
}

func (b *countedBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	n, err := b.reader.Read(p)
	b.bytes.Add(int64(n))
	return n, err
}
func (b *countedBody) Close() error { b.closes.Add(1); return b.closeErr }
func testBody(t testing.TB, ctx context.Context, source io.Reader, owner OwnerKind, length int64, l *Ledger) (*BodyBroker, *countedBody) {
	t.Helper()
	counted := &countedBody{reader: source}
	b, err := NewBodyBroker(ctx, BodySource{Reader: counted, Owner: owner, DeclaredLength: length}, l)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b, counted
}

func TestBodyBufferBoundariesAndIndependentCopies(t *testing.T) {
	for _, limit := range []int{1, 256 << 10, 1 << 20} {
		for _, size := range []int{0, 1, limit - 1, limit, limit + 1} {
			t.Run(fmt.Sprintf("%d/%d", limit, size), func(t *testing.T) {
				data := make([]byte, size)
				for i := range data {
					data[i] = byte(i)
				}
				l := testLedger(t, -1)
				b, source := testBody(t, context.Background(), bytes.NewReader(data), TransportOwned, int64(size), l)
				if err := b.Prepare(context.Background(), None, 0); err != nil || source.reads.Load() != 0 || l.Current() != 0 {
					t.Fatal("None read or allocated")
				}
				err := b.Prepare(context.Background(), FullBuffered, int64(limit))
				if size > limit {
					if !errors.Is(err, ErrBodyLimit) || b.Info().State != PrefixReplay {
						t.Fatal(err)
					}
					if source.bytes.Load() > int64(limit+1) {
						t.Fatal("read beyond lookahead")
					}
					view, err := b.Snapshot(testLease(t, l))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := view.BytesCopy(); !errors.Is(err, ErrBodyUnavailable) {
						t.Fatal("partial body exposed")
					}
					stream, err := b.TakeStream(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(stream)
					if err != nil || !bytes.Equal(got, data) {
						t.Fatal("prefix replay lost bytes", err)
					}
					stream.Close()
				} else {
					if err != nil || b.Info().State != FullBufferedState {
						t.Fatal(err)
					}
					reads := source.reads.Load()
					for copyIndex := 0; copyIndex < 3; copyIndex++ {
						lease := NewCopyLease(l)
						v, err := b.Snapshot(lease)
						if err != nil {
							t.Fatal(err)
						}
						first, err := v.BytesCopy()
						if err != nil || !bytes.Equal(first, data) {
							t.Fatal("binary body changed", err)
						}
						if len(first) > 0 {
							first[0] ^= 255
						}
						second, err := v.BytesCopy()
						if err != nil || !bytes.Equal(second, data) {
							t.Fatal("snapshot bytes alias", err)
						}
						lease.Close()
					}
					if source.reads.Load() != reads {
						t.Fatal("snapshot reread network source")
					}
				}
				b.Close()
				if l.Current() != 0 {
					t.Fatalf("body charge leaked: %d", l.Current())
				}
			})
		}
	}
}

func TestPrefixReplayExtensionAndRepeatLimit(t *testing.T) {
	l := testLedger(t, -1)
	b, source := testBody(t, context.Background(), strings.NewReader("0123456789"), FrameworkOwned, 10, l)
	if err := b.Prepare(context.Background(), FullBuffered, 3); !errors.Is(err, ErrBodyLimit) {
		t.Fatal(err)
	}
	reads := source.reads.Load()
	current := l.Current()
	if err := b.Prepare(context.Background(), FullBuffered, 2); !errors.Is(err, ErrBodyLimit) {
		t.Fatal(err)
	}
	if source.reads.Load() != reads || l.Current() != current {
		t.Fatal("same limit consumed or allocated again")
	}
	if err := b.Prepare(context.Background(), FullBuffered, 10); err != nil {
		t.Fatal(err)
	}
	if source.bytes.Load() != 10 {
		t.Fatal("source bytes consumed twice")
	}
	view, err := b.Snapshot(testLease(t, l))
	if err != nil {
		t.Fatal(err)
	}
	got, err := view.BytesCopy()
	if err != nil || string(got) != "0123456789" {
		t.Fatal(err)
	}
}

type generatedBody struct{ remaining int64 }

func (r *generatedBody) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = 0xa5
	}
	r.remaining -= int64(n)
	return n, nil
}

type shortReader struct{ reader io.Reader }

func (r shortReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.reader.Read(p)
}

type failingReader struct{ err error }

func (r failingReader) Read(p []byte) (int, error) { return copy(p, []byte{0, 255, 0xfe}), r.err }

func TestBodyNoneStreams32MiBWithoutBuffering(t *testing.T) {
	const size = 32 << 20
	l := testLedger(t, 0)
	b, source := testBody(t, context.Background(), &generatedBody{size}, TransportOwned, size, l)
	if err := b.Prepare(context.Background(), None, 0); err != nil || source.reads.Load() != 0 {
		t.Fatal(err)
	}
	stream, err := b.TakeStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.TakeStream(context.Background()); !errors.Is(err, ErrBodyClaimed) {
		t.Fatal(err)
	}
	written, err := io.Copy(io.Discard, stream)
	if err != nil || written != size {
		t.Fatal(written, err)
	}
	if l.Current() != 0 || source.bytes.Load() != size || b.Info().State != UnreadStream {
		t.Fatal("stream buffered or duplicated")
	}
	stream.Close()
	if source.closes.Load() != 1 {
		t.Fatal("stream not closed")
	}
}

func TestBodyShortReadEarlyEOFAndReadError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reader io.Reader
		length int64
		want   error
	}{
		{"short", shortReader{strings.NewReader("abc")}, 3, nil},
		{"early", strings.NewReader("ab"), 3, io.ErrUnexpectedEOF},
		{"excess", strings.NewReader("abc"), 2, io.ErrUnexpectedEOF},
		{"read-error", failingReader{io.ErrClosedPipe}, -1, io.ErrClosedPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := testLedger(t, -1)
			b, source := testBody(t, context.Background(), tc.reader, TransportOwned, tc.length, l)
			err := b.Prepare(context.Background(), FullBuffered, 16)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if tc.want != nil {
				if b.Info().State != Faulted || source.closes.Load() != 1 || l.Current() != 0 {
					t.Fatal("fault retained resources")
				}
				if _, err := b.TakeStream(context.Background()); !errors.Is(err, tc.want) {
					t.Fatal("fault became success")
				}
				if _, err := b.Snapshot(testLease(t, l)); !errors.Is(err, tc.want) {
					t.Fatal("fault snapshot accepted")
				}
			}
		})
	}
}

func TestBodyOwnershipStateMatrix(t *testing.T) {
	for _, owner := range []OwnerKind{ServerOwned, TransportOwned, FrameworkOwned} {
		for _, mode := range []string{"unread", "full", "prefix", "replace", "error", "cancel"} {
			t.Run(fmt.Sprintf("%d/%s", owner, mode), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				l := testLedger(t, -1)
				var reader io.Reader = strings.NewReader("abc")
				if mode == "error" {
					reader = failingReader{io.ErrClosedPipe}
				}
				b, source := testBody(t, ctx, reader, owner, -1, l)
				switch mode {
				case "full":
					if err := b.Prepare(ctx, FullBuffered, 4); err != nil {
						t.Fatal(err)
					}
				case "prefix":
					if err := b.Prepare(ctx, FullBuffered, 1); !errors.Is(err, ErrBodyLimit) {
						t.Fatal(err)
					}
				case "replace":
					data := []byte("new")
					if err := b.Replace(ctx, data); err != nil {
						t.Fatal(err)
					}
					data[0] = 'X'
					view, err := b.Snapshot(testLease(t, l))
					if err != nil {
						t.Fatal(err)
					}
					got, err := view.BytesCopy()
					if err != nil || string(got) != "new" {
						t.Fatal("replacement aliases input")
					}
				case "error":
					if err := b.Prepare(ctx, FullBuffered, 4); !errors.Is(err, io.ErrClosedPipe) {
						t.Fatal(err)
					}
				case "cancel":
					cancel()
					if err := b.Prepare(ctx, FullBuffered, 4); !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
				}
				b.Close()
				b.Close()
				want := int32(1)
				if owner == ServerOwned {
					want = 0
				}
				if source.closes.Load() != want || b.Info().State != Released {
					t.Fatal("ownership violated")
				}
				if _, err := b.TakeStream(ctx); !errors.Is(err, ErrReleased) {
					t.Fatal(err)
				}
				if owner == ServerOwned {
					if mode != "full" && !b.Info().NeedsServerDisposal {
						t.Fatal("unread server source not reported")
					}
					source.Close()
				}
			})
		}
	}
}

type gateReader struct {
	started chan struct{}
	release chan struct{}
	ctx     context.Context
	once    sync.Once
}

func (r *gateReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	if r.ctx != nil {
		select {
		case <-r.ctx.Done():
			return 0, context.Cause(r.ctx)
		case <-r.release:
		}
	}
	if r.ctx == nil {
		<-r.release
	}
	return 0, io.EOF
}

func TestConcurrentBodyReadCancellationAndClose(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	gate := &gateReader{started: make(chan struct{}), release: make(chan struct{}), ctx: ctx}
	l := testLedger(t, -1)
	b, source := testBody(t, ctx, gate, TransportOwned, -1, l)
	done := make(chan error, 1)
	go func() { done <- b.Prepare(ctx, FullBuffered, 1024) }()
	<-gate.started
	cause := errors.New("parent stopped")
	cancel(cause)
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	if err := <-done; !errors.Is(err, cause) {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if l.Current() != 0 || source.closes.Load() != 1 {
		t.Fatal("cancel leaked or double closed")
	}
}

func TestConcurrentBodyUnresponsiveReaderRetainsChargeUntilReadReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gate := &gateReader{started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(gate.release) }) }
	defer unblock()
	l := testLedger(t, -1)
	b, source := testBody(t, ctx, gate, TransportOwned, -1, l)
	done := make(chan error, 1)
	go func() { done <- b.Prepare(ctx, FullBuffered, 1024) }()
	<-gate.started
	cancel()
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	select {
	case <-closed:
		t.Fatal("Close claimed to interrupt arbitrary Reader")
	case <-time.After(10 * time.Millisecond):
	}
	if l.Current() == 0 || source.closes.Load() != 0 {
		t.Fatal("charge/source released during Read")
	}
	unblock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if l.Current() != 0 || source.closes.Load() != 1 {
		t.Fatal("late read leaked")
	}
}

func TestBodyBudgetRejectsBeforeReadAndSnapshotChargesSurviveClose(t *testing.T) {
	l := testLedger(t, 1024)
	b, source := testBody(t, context.Background(), strings.NewReader("abc"), TransportOwned, 3, l)
	if err := b.Prepare(context.Background(), FullBuffered, 1024); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
	if source.reads.Load() != 0 || l.Current() != 0 {
		t.Fatal("budget check too late")
	}
	if err := b.Prepare(context.Background(), FullBuffered, 3); err != nil {
		t.Fatal(err)
	}
	lease := NewCopyLease(l)
	view, err := b.Snapshot(lease)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	if l.Current() == 0 {
		t.Fatal("input released with broker")
	}
	limited := false
	for i := 0; i < 20; i++ {
		_, err = view.BytesCopy()
		if errors.Is(err, ErrResourceLimit) {
			limited = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !limited {
		t.Fatal("Body.BytesCopy bypassed budget")
	}
	lease.Close()
	lease.Close()
	if l.Current() != 0 {
		t.Fatal("copy charge leaked")
	}
	if data, err := view.BytesCopy(); !errors.Is(err, ErrReleased) || data != nil {
		t.Fatal("released view still delivered bytes")
	}
}

func TestBodyCloseErrorsAndUnavailable(t *testing.T) {
	l := testLedger(t, -1)
	b, source := testBody(t, context.Background(), strings.NewReader("x"), TransportOwned, 1, l)
	source.closeErr = io.ErrClosedPipe
	if err := b.Replace(context.Background(), []byte("y")); !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, ErrCleanupFailure) {
		t.Fatal(err)
	}
	if b.Info().State != Faulted || l.Current() != 0 {
		t.Fatal("failed replacement remained usable")
	}
	if !errors.Is(b.Close(), io.ErrClosedPipe) || !errors.Is(b.Close(), io.ErrClosedPipe) || source.closes.Load() != 1 {
		t.Fatal("close error lost or close duplicated")
	}
	unavailable, err := NewBodyBroker(context.Background(), BodySource{Owner: ServerOwned, DeclaredLength: -1}, l)
	if err != nil {
		t.Fatal(err)
	}
	if err := unavailable.Prepare(context.Background(), FullBuffered, 1); !errors.Is(err, ErrBodyUnavailable) {
		t.Fatal(err)
	}
}

func TestConcurrentBodyPrepareReplaceAndSingleConsumer(t *testing.T) {
	l := testLedger(t, -1)
	b, source := testBody(t, context.Background(), strings.NewReader("old"), TransportOwned, 3, l)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-gate
		if err := b.Prepare(context.Background(), FullBuffered, 16); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wg.Done()
		<-gate
		if err := b.Replace(context.Background(), []byte("new")); err != nil {
			t.Error(err)
		}
	}()
	close(gate)
	wg.Wait()
	lease := NewCopyLease(l)
	view, err := b.Snapshot(lease)
	if err != nil {
		t.Fatal(err)
	}
	data, err := view.BytesCopy()
	if err != nil || string(data) != "new" {
		t.Fatal("replacement not serialized", err)
	}
	gate = make(chan struct{})
	streams := make(chan io.ReadCloser, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			<-gate
			stream, err := b.TakeStream(context.Background())
			if err == nil {
				streams <- stream
			} else if !errors.Is(err, ErrBodyClaimed) {
				t.Error(err)
			}
		}()
	}
	close(gate)
	wg.Wait()
	close(streams)
	if len(streams) != 1 {
		t.Fatal("multiple stream consumers")
	}
	stream := <-streams
	data, err = io.ReadAll(stream)
	if err != nil || string(data) != "new" {
		t.Fatal("stream changed", err)
	}
	stream.Close()
	lease.Close()
	if source.closes.Load() != 1 || source.bytes.Load() > 3 || l.Current() != 0 {
		t.Fatal("serialized operations leaked resources")
	}
}
