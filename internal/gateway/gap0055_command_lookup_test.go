// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP0055CommandLookupFourCell is gas-ux-r1 GAP-0055: since 1.0.7 a
// shell command that reaches unzip with no arguments (command -v unzip,
// command -v unzip && command -v tar, env unzip, a bare unzip) panicked in
// the hook evaluator. The per-user gateway recovered and failed closed as
// "defenseclaw internal evaluator error" with no rule id; the managed hook
// client panicked before it asked the gateway. Each form is now allowed
// for both connectors, managed and per-user, without the panic answer; a
// lookup with more operands runs nothing and is allowed too. The protected
// twins (a later write through the project's authorized_keys link, an
// extraction that really runs) keep their block.
func TestGAP0055CommandLookupFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.project, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command, want string }{
		{"lookup-and", `command -v unzip && command -v tar`, "allow"},
		{"lookup", `command -v unzip`, "allow"},
		{"lookup-semicolon", `command -v unzip; command -v tar`, "allow"},
		{"lookup-or-exit", `command -v unzip || exit 1`, "allow"},
		{"lookup-three", `command -v unzip && command -v tar && command -v 7z`, "allow"},
		{"lookup-upper-v", `command -V unzip`, "allow"},
		{"lookup-quiet", `command -v unzip >/dev/null 2>&1 && echo yes`, "allow"},
		{"env-bare", `env unzip`, "allow"},
		{"command-bare", `command unzip`, "allow"},
		{"bare", `unzip`, "allow"},
		{"sudo-version", `sudo -n unzip -v`, "allow"},
		{"lookup-then-copy", `command -v unzip && cp a.txt build/`, "allow"},
		{"lookup-operands-then-copy", `command -v unzip x.zip; cp a.txt build/`, "allow"},
		{"lookup-then-protected-copy", `command -v unzip && cp a.txt keylink`, "block"},
		{"lookup-then-protected-write", `command -v unzip && echo hi > keylink`, "block"},
		{"command-extract-then-copy", `command unzip x.zip; cp a.txt build/`, "block"},
		{"env-extract-then-copy", `env unzip x.zip; cp a.txt build/`, "block"},
	}
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := make([]*hookCall, 0, 4*len(rows))
	for _, row := range rows {
		payload := f.payload(t, row.command)
		var header string
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("%s: managed hook client panic: %v", row.name, recovered)
				}
			}()
			header = hookpaths.Resolve(payload)
		}()
		calls = append(calls, everyMode(row.name, payload, header)...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		if want := rows[i/4].want; call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.300s", call.name, call.verdict, want, call.body)
		}
		if strings.Contains(call.body, "internal evaluator error") || strings.Contains(call.body, "panics.total") {
			t.Errorf("%s: panic answer: %.300s", call.name, call.body)
		}
	}
}
