//go:build quickjs && cgo

package quickjs

import (
	"testing"

	"github.com/dop251/goja"
)

const benchmarkSource = "String((1 + 2) * 3)"

var (
	gojaRuntimeBenchmarkSink *goja.Runtime
	gojaProgramBenchmarkSink *goja.Program
)

func BenchmarkRuntimeCreate(b *testing.B) {
	b.Run("QuickJS", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			runtime, err := NewRuntime(RuntimeOptions{})
			if err != nil {
				b.Fatal(err)
			}
			if err := runtime.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("GojaVM", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			gojaRuntimeBenchmarkSink = goja.New()
		}
	})
}

func BenchmarkContextCreate(b *testing.B) {
	runtime, err := NewRuntime(RuntimeOptions{})
	if err != nil {
		b.Fatal(err)
	}
	defer runtime.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		context, err := runtime.NewContext()
		if err != nil {
			b.Fatal(err)
		}
		if err := context.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSimpleEval(b *testing.B) {
	b.Run("QuickJS", func(b *testing.B) {
		runtime, err := NewRuntime(RuntimeOptions{})
		if err != nil {
			b.Fatal(err)
		}
		context, err := runtime.NewContext()
		if err != nil {
			b.Fatal(err)
		}
		defer runtime.Close()
		defer context.Close()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := context.Eval(benchmarkSource); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("GojaVM", func(b *testing.B) {
		vm := goja.New()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			value, err := vm.RunString(benchmarkSource)
			if err != nil {
				b.Fatal(err)
			}
			_ = value.Export().(string)
		}
	})
}

func BenchmarkCompile(b *testing.B) {
	b.Run("QuickJS", func(b *testing.B) {
		runtime, err := NewRuntime(RuntimeOptions{})
		if err != nil {
			b.Fatal(err)
		}
		context, err := runtime.NewContext()
		if err != nil {
			b.Fatal(err)
		}
		defer runtime.Close()
		defer context.Close()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			script, err := context.Compile(benchmarkSource)
			if err != nil {
				b.Fatal(err)
			}
			if err := script.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Goja", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			program, err := goja.Compile("m61-benchmark.js", benchmarkSource, false)
			if err != nil {
				b.Fatal(err)
			}
			gojaProgramBenchmarkSink = program
		}
	})
}

func BenchmarkCompiledExecution(b *testing.B) {
	b.Run("QuickJS", func(b *testing.B) {
		runtime, err := NewRuntime(RuntimeOptions{})
		if err != nil {
			b.Fatal(err)
		}
		context, err := runtime.NewContext()
		if err != nil {
			b.Fatal(err)
		}
		script, err := context.Compile(benchmarkSource)
		if err != nil {
			b.Fatal(err)
		}
		defer runtime.Close()
		defer context.Close()
		defer script.Close()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := script.Eval(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Goja", func(b *testing.B) {
		program, err := goja.Compile("m61-benchmark.js", benchmarkSource, false)
		if err != nil {
			b.Fatal(err)
		}
		vm := goja.New()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			value, err := vm.RunProgram(program)
			if err != nil {
				b.Fatal(err)
			}
			_ = value.Export().(string)
		}
	})
}

func BenchmarkJSGoBoundaryString(b *testing.B) {
	const source = "'abcdefghijabcdefghijabcdefghijabcdefghij'"
	b.Run("QuickJS", func(b *testing.B) {
		runtime, err := NewRuntime(RuntimeOptions{})
		if err != nil {
			b.Fatal(err)
		}
		context, err := runtime.NewContext()
		if err != nil {
			b.Fatal(err)
		}
		script, err := context.Compile(source)
		if err != nil {
			b.Fatal(err)
		}
		defer runtime.Close()
		defer context.Close()
		defer script.Close()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := script.Eval(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Goja", func(b *testing.B) {
		vm := goja.New()
		program, err := goja.Compile("m61-boundary.js", source, false)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			value, err := vm.RunProgram(program)
			if err != nil {
				b.Fatal(err)
			}
			_ = value.Export().(string)
		}
	})
}
