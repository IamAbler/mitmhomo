package httphook

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type hookMemorySample struct {
	HeapAlloc   uint64
	HeapObjects uint64
	HeapInuse   uint64
	Goroutines  int
	RSS         uint64
}

func sampleHookMemory() hookMemorySample {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return hookMemorySample{
		HeapAlloc:   stats.HeapAlloc,
		HeapObjects: stats.HeapObjects,
		HeapInuse:   stats.HeapInuse,
		Goroutines:  runtime.NumGoroutine(),
		RSS:         readHookRSS(),
	}
}

func readHookRSS() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kib, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kib * 1024
	}
	return 0
}

func TestHTTPHookMemoryLifecycleSnapshots(t *testing.T) {
	if testing.Short() {
		t.Skip("memory lifecycle snapshot")
	}
	baseline := sampleHookMemory()
	snapshot, err := Compile(Config{Enable: true, Rules: []Rule{{
		Name: "memory", Phase: RequestPhase, Match: Match{Path: "/memory"}, Source: `null`,
	}}})
	require.NoError(t, err)
	configured := sampleHookMemory()
	require.False(t, snapshot.RuntimeInitialized())

	request, err := http.NewRequest(http.MethodPost, "https://memory.example.test/memory", strings.NewReader("bounded request body"))
	require.NoError(t, err)
	_, err = snapshot.ApplyRequest(context.Background(), request)
	require.NoError(t, err)
	require.True(t, snapshot.RuntimeInitialized())
	firstRun := sampleHookMemory()

	for i := 0; i < 500; i++ {
		request.Body = io.NopCloser(strings.NewReader(fmt.Sprintf("request-%d", i)))
		_, err = snapshot.ApplyRequest(context.Background(), request)
		require.NoError(t, err)
	}
	steady := sampleHookMemory()
	require.NoError(t, snapshot.Close())
	closed := sampleHookMemory()

	t.Logf("M4.2 HTTP hook memory bytes (RSS=0 means unavailable): baseline=%+v configured=%+v first_run=%+v after_500=%+v closed_gc=%+v", baseline, configured, firstRun, steady, closed)
}
