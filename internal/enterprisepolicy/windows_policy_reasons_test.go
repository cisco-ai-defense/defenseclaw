// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

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

// A missing Windows machine hook is drift even when no user is enrolled.
// Keep that contract in the diagnostics emitted by policy and the guardian.
func TestWindowsPolicyReasonsDoNotConditionPublicationOnEnrollment(t *testing.T) {
	for _, dir := range []string{".", "../enterprisehooks"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.Contains(name, "windows") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				spec, ok := node.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for _, ident := range spec.Names {
					if !strings.HasSuffix(ident.Name, "Reason") && !strings.HasSuffix(ident.Name, "Consequence") {
						continue
					}
					for _, value := range spec.Values {
						literal, ok := value.(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							continue
						}
						message, err := strconv.Unquote(literal.Value)
						if err != nil {
							t.Errorf("%s: %v", path, err)
							continue
						}
						lower := strings.ToLower(message)
						if strings.Contains(lower, "only while") || strings.Contains(lower, "at least one user is enrolled") {
							t.Errorf("%s: %s conditions machine-hook publication on enrollment", path, ident.Name)
						}
					}
				}
				return false
			})
		}
	}
}
