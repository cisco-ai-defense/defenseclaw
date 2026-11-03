// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// The known-word reader and the statement directory walk must accept the
// same leading directory forms. Otherwise the client can omit a destination
// that the gateway treats as a known copy word (GAP-0402).
func TestGAP0402SharedDirectoryChangeOperand(t *testing.T) {
	home := t.TempDir()
	for _, row := range []struct {
		name, command, operand string
		accept                 bool
	}{
		{"cd logical", `cd -L build && cp a b`, "build", true},
		{"cd end options", `cd -- build && cp a b`, "build", true},
		{"cd logical end options", `cd -L -- build && cp a b`, "build", true},
		{"cd repeated logical", `cd -L -L build && cp a b`, "build", true},
		{"pushd", `pushd ./build && cp a b`, "./build", true},
		{"cd physical", `cd -P build && cp a b`, "", false},
		{"pushd option", `pushd -n ./build && cp a b`, "", false},
		{"pushd stack index", `pushd +1 && cp a b`, "", false},
		{"cd dash operand", `cd - && cp a b`, "", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, ok := parseShell(row.command)
			if !ok {
				t.Fatal("command did not parse")
			}
			pair, ok := file.Stmts[0].Cmd.(*syntax.BinaryCmd)
			if !ok {
				t.Fatal("missing AND list")
			}
			operand, accepted := leadingDirectoryOperand(pair.X, home)
			if accepted != row.accept || operand != row.operand {
				t.Fatalf("known-word operand = %q, %t; want %q, %t", operand, accepted, row.operand, row.accept)
			}
			statements, dirs, known := topLevelStatementDirectories(file, home, home)
			placed := known && len(statements) == 1 && len(dirs) == 1 && dirs[0] == filepath.Join(home, row.operand)
			if placed != row.accept {
				t.Fatalf("statement placed = %t (known=%t, statements=%d, dirs=%v); want %t", placed, known, len(statements), dirs, row.accept)
			}
		})
	}
}
