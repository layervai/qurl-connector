package main

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"strings"
	"testing"
)

// sharedServiceBody returns the source of startSharedService, bounded to its own
// body so a later function cannot satisfy these assertions from outside it.
func sharedServiceBody(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatalf("read run.go: %v", err)
	}
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, "run.go", content, 0)
	if err != nil {
		t.Fatalf("parse run.go: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "startSharedService" || fn.Body == nil {
			continue
		}
		return string(content[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
	}
	t.Fatal("startSharedService not found")
	return ""
}

// TestSharedServiceServesEveryConfiguredResource pins the multi-resource
// contract.
//
// One resource per process made a multi-resource client impossible without
// supervising a process per share. qURL Desktop crashlooped the moment a user
// shared a second file: the Connector refused to start at all, so the first
// share stopped working too. The admitter is built for this -- per-resource
// locks, plural recovery enumeration, a mutex-guarded MarkServingHealthy -- so
// the restriction was in this function alone.
func TestSharedServiceServesEveryConfiguredResource(t *testing.T) {
	t.Parallel()
	body := sharedServiceBody(t)

	if strings.Contains(body, "exactly one resource per process") {
		t.Error("the one-resource restriction is back; a second share will crashloop the Connector")
	}
	if strings.Contains(body, "len(qcfg.Routes) != 1") {
		t.Error("startSharedService still rejects multi-resource configs")
	}
	if !strings.Contains(body, "for _, route := range qcfg.Routes") {
		t.Error("every configured route must get a runner, not just the first")
	}
	// A terminal failure on one resource must not leave the others serving in a
	// process no supervisor can reason about.
	if !strings.Contains(body, "errgroup.WithContext(ctx)") {
		t.Error("sibling runners must share a cancellation scope")
	}
	// An empty config is still an error: there is nothing to serve.
	if !strings.Contains(body, "len(qcfg.Routes) == 0") {
		t.Error("an empty route set must still be rejected")
	}
}
