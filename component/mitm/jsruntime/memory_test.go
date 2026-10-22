package jsruntime

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestRuntimeMemoryLifecycleSnapshots(t *testing.T) {
	logSnapshot := func(stage string) {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		rss := readProcessRSS()
		t.Logf("%s: HeapAlloc=%d HeapObjects=%d HeapInuse=%d HeapReleased=%d NumGoroutine=%d RSS=%d", stage, stats.HeapAlloc, stats.HeapObjects, stats.HeapInuse, stats.HeapReleased, runtime.NumGoroutine(), rss)
	}

	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()
	logSnapshot("runtime not created (Goja package init already ran)")

	config := testConfig()
	config.CompileCacheEntries = 16
	r := newTestRuntime(t, config)
	if r.cache.entries != nil || r.activeVMs != nil {
		t.Fatal("New allocated a compile cache map or initialized a VM registry before first use")
	}
	if got := runtime.NumGoroutine(); got != baselineGoroutines {
		t.Fatalf("New created a goroutine: before=%d after=%d", baselineGoroutines, got)
	}
	logSnapshot("runtime created, no script")

	if _, err := r.Run(context.Background(), `input.value + 1`, map[string]int{"value": 1}); err != nil {
		t.Fatal(err)
	}
	logSnapshot("first script execution")

	for index := 0; index < 500; index++ {
		source := fmt.Sprintf("input.value + %d", index)
		if _, err := r.Run(context.Background(), source, map[string]int{"value": index}); err != nil {
			t.Fatalf("script %d: %v", index, err)
		}
	}
	logSnapshot("500 unique scripts, bounded cache")

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r.cache.entries != nil || len(r.activeVMs) != 0 {
		t.Fatal("Close retained the internal compile cache or VM registry")
	}
	logSnapshot("runtime closed")
	runtime.GC()
	logSnapshot("GC after close")

	recreated := newTestRuntime(t, config)
	if _, err := recreated.Run(context.Background(), `42`, nil); err != nil {
		t.Fatal(err)
	}
	logSnapshot("new runtime after close")
	if err := recreated.Close(); err != nil {
		t.Fatal(err)
	}
}

func readProcessRSS() uint64 {
	contents, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		return value * 1024
	}
	return 0
}
