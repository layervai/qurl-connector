package main

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"testing"
)

// TestResourceConfigReportsAdmissionRetries pins the OnRetry wiring.
//
// share.ResourceConfig.OnRetry is the ResourceRunner's only channel for a failed
// admission attempt (pkg/share/session.go reportRetry). While it was unset the
// Connector logged an endless "retrying" with no reason, so a Connector that
// could never be admitted was indistinguishable from one that was merely slow.
// That cost weeks of debugging on qURL Desktop. If this literal ever loses
// OnRetry again, fail here rather than in the field.
func TestResourceConfigReportsAdmissionRetries(t *testing.T) {
	t.Parallel()
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, "run.go", nil, 0)
	if err != nil {
		t.Fatalf("parse run.go: %v", err)
	}

	found, wired := false, false
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ResourceConfig" {
			return true
		}
		found = true
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "OnRetry" {
				wired = true
			}
		}
		return true
	})

	if !found {
		t.Fatal("no share.ResourceConfig literal in run.go; update this guard if the construction moved")
	}
	if !wired {
		t.Error("share.ResourceConfig does not set OnRetry, so every admission failure is discarded and " +
			"an unadmittable Connector logs only an unexplained retry loop")
	}
}
