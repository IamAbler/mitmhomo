package pipeline

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

func TestPipelineDependencyBoundary(t *testing.T) {
	allowed := map[string]bool{
		"context": true, "errors": true, "fmt": true, "io": true, "sort": true,
		"sync": true, "sync/atomic": true,
		"github.com/metacubex/mihomo/component/mitm/processing/model":     true,
		"github.com/metacubex/mihomo/component/mitm/processing/processor": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			name, _ := strconv.Unquote(spec.Path.Value)
			if !allowed[name] {
				t.Errorf("forbidden Pipeline dependency %s: %s", entry.Name(), name)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if _, ok := node.(*ast.GoStmt); ok {
				t.Errorf("Pipeline starts background goroutine: %s", entry.Name())
			}
			return true
		})
	}
}
