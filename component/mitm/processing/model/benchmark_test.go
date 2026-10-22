package model

import (
	"context"
	"io"
	"strings"
	"testing"
)

func BenchmarkHeaderBlockClone(b *testing.B) {
	l := testLedger(b, -1)
	source := testLease(b, l)
	h, err := NewHeaderBlock(source, []HeaderField{{"Content-Type", []string{"application/octet-stream"}}, {"Set-Cookie", []string{"a=1", "b=2"}}})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease := NewCopyLease(l)
		if _, err := h.Clone(lease); err != nil {
			b.Fatal(err)
		}
		lease.Close()
	}
}
func BenchmarkURLValueParseAndSnapshot(b *testing.B) {
	l := testLedger(b, -1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease := NewCopyLease(l)
		u, err := ParseURL(lease, "https://example.test/a%2Fb?b=2&a=&b=1&x=%2f", MITMHTTPS)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := u.clone(lease); err != nil {
			b.Fatal(err)
		}
		lease.Close()
	}
}
func BenchmarkBodyNone(b *testing.B) {
	l := testLedger(b, 0)
	body, err := NewBodyBroker(context.Background(), BodySource{Reader: io.NopCloser(strings.NewReader("not read")), Owner: TransportOwned, DeclaredLength: -1}, l)
	if err != nil {
		b.Fatal(err)
	}
	defer body.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := body.Prepare(context.Background(), None, 0); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkBodyFullBuffered(b *testing.B) {
	l := testLedger(b, -1)
	payload := strings.Repeat("x", 64<<10)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body, err := NewBodyBroker(context.Background(), BodySource{Reader: io.NopCloser(strings.NewReader(payload)), Owner: TransportOwned, DeclaredLength: int64(len(payload))}, l)
		if err != nil {
			b.Fatal(err)
		}
		if err := body.Prepare(context.Background(), FullBuffered, int64(len(payload))); err != nil {
			b.Fatal(err)
		}
		body.Close()
	}
}
func BenchmarkBodyPrefixReplay(b *testing.B) {
	l := testLedger(b, -1)
	payload := strings.Repeat("x", 64<<10)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body, err := NewBodyBroker(context.Background(), BodySource{Reader: io.NopCloser(strings.NewReader(payload)), Owner: TransportOwned, DeclaredLength: int64(len(payload))}, l)
		if err != nil {
			b.Fatal(err)
		}
		if err := body.Prepare(context.Background(), FullBuffered, 1024); err != ErrBodyLimit {
			b.Fatal(err)
		}
		stream, err := body.TakeStream(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, stream); err != nil {
			b.Fatal(err)
		}
		stream.Close()
	}
}
func BenchmarkBodySnapshotCopy(b *testing.B) {
	l := testLedger(b, -1)
	payload := strings.Repeat("x", 64<<10)
	body, err := NewBodyBroker(context.Background(), BodySource{Reader: io.NopCloser(strings.NewReader(payload)), Owner: TransportOwned, DeclaredLength: int64(len(payload))}, l)
	if err != nil {
		b.Fatal(err)
	}
	defer body.Close()
	if err := body.Prepare(context.Background(), FullBuffered, int64(len(payload))); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease := NewCopyLease(l)
		view, err := body.Snapshot(lease)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := view.BytesCopy(); err != nil {
			b.Fatal(err)
		}
		lease.Close()
	}
}
func BenchmarkBudgetReserveRelease(b *testing.B) {
	shared, _ := NewBudget(-1)
	ledger, _ := NewLedger(-1, shared)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ticket, err := ledger.Reserve(4096)
		if err != nil {
			b.Fatal(err)
		}
		ticket.Release()
	}
}
