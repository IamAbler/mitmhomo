package model

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestModelDependencyBoundary(t *testing.T) {
	// Exact stdlib allowlist: engine, host, parent MITM, native and IPC imports
	// cannot accidentally enter the leaf model package.
	allowed := map[string]bool{"context": true, "errors": true, "fmt": true, "math": true, "sync": true, "sync/atomic": true, "net/textproto": true, "strings": true, "net/url": true, "strconv": true, "io": true, "time": true}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			name, _ := strconv.Unquote(spec.Path.Value)
			if !allowed[name] {
				t.Errorf("forbidden dependency %s: %s", entry.Name(), name)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if _, ok := node.(*ast.GoStmt); ok {
				t.Errorf("model starts a goroutine: %s", entry.Name())
			}
			return true
		})
	}
	// The processor and pipeline layers are the only intentional production
	// dependencies on the model. No protocol, engine, or existing production
	// package may import it.
	const target = "github.com/metacubex/mihomo/component/mitm/processing/model"
	root := filepath.Clean("../../../..")
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || path == filepath.Join(root, "component", "mitm", "processing", "model") || path == filepath.Join(root, "component", "mitm", "processing", "processor") || path == filepath.Join(root, "component", "mitm", "processing", "pipeline") || strings.HasPrefix(entry.Name(), ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			name, _ := strconv.Unquote(spec.Path.Value)
			if name == target {
				t.Errorf("model connected to production path: %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
