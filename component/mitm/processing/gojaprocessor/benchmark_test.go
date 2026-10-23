package gojaprocessor

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/dop251/goja"
	"github.com/metacubex/mihomo/component/mitm/jsruntime"
	"github.com/metacubex/mihomo/component/mitm/processing/model"
	"github.com/metacubex/mihomo/component/mitm/processing/processor"
)

const benchmarkContinueSource = `function process(input) { return {kind:"continue"}; }`
const benchmarkHeaderSource = `function process(input) { return {kind:"request_change",request:{headers:[{op:"set",name:"X-Bench",values:["value"]}]}}; }`
const benchmarkBodySource = `function process(input) { return {kind:"request_change",request:{body:{encoding:"base64",data:"cmVwbGFjZWQ="}}}; }`

func BenchmarkGojaProcessorFactoryBuild(b *testing.B) {
	config := testConfig(benchmarkContinueSource)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend, err := New(config)
		if err != nil {
			b.Fatal(err)
		}
		_ = backend.Close()
		if err := backend.WaitClosed(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGojaProgramCompile(b *testing.B) {
	config := jsruntime.DefaultConfig()
	config.MaxSourceBytes = len(entryPrefix) + len(benchmarkContinueSource) + len(entrySuffix)
	config.CompileCacheEntries = 0
	runtime, err := jsruntime.New(config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = runtime.Close() })
	source := entryPrefix + benchmarkContinueSource + entrySuffix
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := runtime.Compile(source); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGojaVMCreation(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = goja.New()
	}
}

func BenchmarkGojaRuntimeManagerCreation(b *testing.B) {
	config := jsruntime.DefaultConfig()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runtime, err := jsruntime.New(config)
		if err != nil {
			b.Fatal(err)
		}
		_ = runtime.Close()
	}
}

func BenchmarkGojaSimpleContinue(b *testing.B) {
	benchmarkProcessorRun(b, benchmarkContinueSource, nil)
}

func BenchmarkGojaHeaderModification(b *testing.B) {
	benchmarkProcessorRun(b, benchmarkHeaderSource, nil)
}

func BenchmarkGojaBodyModification(b *testing.B) {
	benchmarkProcessorRun(b, benchmarkBodySource, nil)
}

func benchmarkProcessorRun(b *testing.B, source string, body []byte) {
	b.Helper()
	backend := newTestProcessor(b, testConfig(source))
	tx := testTransaction(b, 7, body)
	input, inputLease, err := tx.Snapshot("benchmark-goja")
	if err != nil {
		b.Fatal(err)
	}
	defer inputLease.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := backend.run(context.Background(), input, backend.program)
		if err != nil {
			b.Fatal(err)
		}
		_ = result.Release()
	}
}

func BenchmarkGojaConcurrentInvocations(b *testing.B) {
	config := testConfig(benchmarkContinueSource)
	config.Capacity = processor.DefaultInvocationCapacity
	backend := newTestProcessor(b, config)
	tx := testTransaction(b, 7, nil)
	var sequence atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			input, lease, err := tx.Snapshot(model.InvocationID("bench-" + decimalUint(sequence.Add(1))))
			if err != nil {
				b.Error(err)
				return
			}
			invocation, err := backend.Start(context.Background(), input, lease)
			if err != nil {
				_ = lease.Close()
				b.Error(err)
				return
			}
			result, err := invocation.Await(context.Background())
			if err != nil {
				b.Error(err)
				return
			}
			_ = result.Release()
			<-invocation.ExecutionDone()
		}
	})
}

func decimalUint(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}
