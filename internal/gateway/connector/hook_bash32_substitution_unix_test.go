// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestRenderedShellHooksKeepCaseOutOfCommandSubstitutions is
// rel-1-0-6:GAP-0434. macOS runs the shell hooks with /bin/bash 3.2, which
// ends a $( ) or <( ) at the ")" of a case pattern. bash -n accepts such a
// file, because 3.2 parses a substitution only when it runs, so the hook
// then failed on every call ("command substitution: syntax error:
// unexpected end of file") and only the macOS lifecycle and contract jobs
// saw it. A newer bash and this parser read the same text correctly, so
// the test renders every connector's per-user hooks (with _hardening.sh)
// and refuses any case clause inside a command or process substitution;
// keep the case in the enclosing function, or in a function the
// substitution calls.
func TestRenderedShellHooksKeepCaseOutOfCommandSubstitutions(t *testing.T) {
	names := make([]string, 0, len(connectorHookScripts))
	for name := range connectorHookScripts {
		names = append(names, name)
	}
	sort.Strings(names)
	checked := map[string]bool{}
	for _, name := range names {
		dir := t.TempDir()
		if err := WriteHookScriptsForConnector(dir, "127.0.0.1:18970", "tok-test", name); err != nil {
			t.Fatalf("%s: render hooks: %v", name, err)
		}
		scripts, err := filepath.Glob(filepath.Join(dir, "*.sh"))
		if err != nil {
			t.Fatal(err)
		}
		for _, script := range scripts {
			checked[filepath.Base(script)] = true
			data, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			label := name + "/" + filepath.Base(script)
			file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(string(data)), label)
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			syntax.Walk(file, func(node syntax.Node) bool {
				var inner []*syntax.Stmt
				switch node := node.(type) {
				case *syntax.CmdSubst:
					inner = node.Stmts
				case *syntax.ProcSubst:
					inner = node.Stmts
				default:
					return true
				}
				for _, stmt := range inner {
					syntax.Walk(stmt, func(child syntax.Node) bool {
						if clause, ok := child.(*syntax.CaseClause); ok {
							t.Errorf("%s:%s: case statement inside the substitution opened at %s; macOS /bin/bash 3.2 cannot parse it",
								label, clause.Pos(), node.Pos())
						}
						return true
					})
				}
				return false
			})
		}
	}
	for _, want := range []string{"_hardening.sh", "inspect-tool.sh", "claude-code-hook.sh", "codex-hook.sh", "cursor-hook.sh"} {
		if !checked[want] {
			t.Errorf("rendered hooks did not include %s (checked %v)", want, checked)
		}
	}
}
