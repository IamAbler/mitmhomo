package mitm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/mitm/processing/model"
)

type observedInboundReader struct {
	io.ReadCloser
	entered chan struct{}
	once    sync.Once
}

func (r *observedInboundReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	return r.ReadCloser.Read(p)
}
func protocolBodyAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("protocol body wait timed out")
	}
	var zero T
	return zero
}

func TestInboundBodyInterruptProtocolOwnership(t *testing.T) {
	for _, mode := range []string{"h1-deadline", "h2-deadline", "h2-client-cancel"} {
		t.Run(mode, func(t *testing.T) {
			h2 := mode != "h1-deadline"
			type pending struct {
				broker  *model.BodyBroker
				cancel  context.CancelCauseFunc
				entered <-chan struct{}
			}
			started := make(chan pending, 1)
			results := make(chan error, 1)
			var good, unexpected atomic.Int32
			harness := newProtocolHarness(t, nil, "localhost", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/blocked" {
					unexpected.Add(1)
				} else {
					good.Add(1)
				}
				_, _ = io.WriteString(w, "ok")
			}), false, true, h2, []string{"http/1.1"}, func(config *Config) {
				config.RequestHook = func(request *http.Request) error {
					if request.URL.Path != "/blocked" {
						return nil
					}
					source, ok := InboundBodySourceFromContext(request.Context())
					if !ok || source.Interrupt == nil {
						err := errors.New("missing certified inbound Body capability")
						results <- err
						return err
					}
					observed := &observedInboundReader{ReadCloser: source.Reader, entered: make(chan struct{})}
					ledger, _ := model.NewLedger(-1, nil)
					broker, err := model.NewBodyBroker(request.Context(), model.BodySource{Reader: observed, Owner: model.ServerOwned, DeclaredLength: -1, Interrupt: source.Interrupt}, ledger)
					if err != nil {
						results <- err
						return err
					}
					ctx, cancel := context.WithCancelCause(request.Context())
					defer cancel(context.Canceled)
					started <- pending{broker, cancel, observed.entered}
					err = broker.Prepare(ctx, model.FullBuffered, 1024)
					wait, stop := context.WithTimeout(context.Background(), time.Second)
					defer stop()
					closeErr := broker.CloseContext(wait)
					if closeErr != nil {
						results <- closeErr
						return closeErr
					}
					select {
					case <-broker.ExecutionDone():
					default:
						results <- errors.New("early logical close without physical completion")
						return errors.New("not drained")
					}
					if ledger.Current() != 0 {
						results <- fmt.Errorf("body leaked %d bytes", ledger.Current())
						return errors.New("leaked")
					}
					results <- err
					return err
				}
			})
			upload, writer := io.Pipe()
			defer upload.Close()
			defer writer.Close()
			clientCtx, cancelClient := context.WithCancel(context.Background())
			defer cancelClient()
			request, _ := http.NewRequestWithContext(clientCtx, "POST", "https://localhost/blocked", upload)
			responseDone := make(chan error, 1)
			go func() {
				response, err := harness.wire.RoundTrip(request)
				if response != nil {
					_, _ = io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode < 400 {
						err = fmt.Errorf("blocked upload returned %d", response.StatusCode)
					}
				}
				responseDone <- err
			}()
			if _, err := writer.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			active := protocolBodyAwait(t, started)
			protocolBodyAwait(t, active.entered)
			sibling := func() {
				request, _ := http.NewRequest("GET", "https://localhost/sibling", nil)
				response, err := harness.wire.RoundTrip(request)
				if err != nil {
					t.Fatal("sibling stream failed", err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(body) != "ok" || response.ProtoMajor != 2 {
					t.Fatal("sibling response", string(body), err)
				}
			}
			if h2 {
				sibling()
			} // Prove a sibling works while the original Read is blocked.
			if mode == "h2-client-cancel" {
				cancelClient()
			} else {
				active.cancel(context.DeadlineExceeded)
			}
			err := protocolBodyAwait(t, results)
			expected := context.DeadlineExceeded
			if mode == "h2-client-cancel" {
				expected = context.Canceled
			}
			if !errors.Is(err, expected) {
				t.Fatal("wrong cancellation cause", err)
			}
			writer.Close()
			_ = protocolBodyAwait(t, responseDone) // HTTP error response or client cancellation.
			if h2 {
				sibling()
				if good.Load() != 2 {
					t.Fatal("sibling requests missing")
				}
			}
			if unexpected.Load() != 0 {
				t.Fatal("canceled upload reached main upstream")
			}
		})
	}
}
