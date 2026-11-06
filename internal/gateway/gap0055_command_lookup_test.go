// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
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
		// Review M1: xargs supplies the archive names, so the argv the hook
		// sees is not the one unzip gets; the extraction keeps its opaque
		// scope, as on 1.0.6. A visible list mode stays allowed.
		{"xargs-then-copy", `ls *.zip | xargs unzip; cp a.txt build/`, "block"},
		{"xargs-n1-then-copy", `find . -name '*.zip' | xargs -n1 unzip; cp a.txt build/`, "block"},
		{"xargs-0-then-copy", `find . -name '*.zip' -print0 | xargs -0 unzip && cp a.txt build/`, "block"},
		{"xargs-a-then-copy", `xargs -a list.txt unzip; cp a.txt build/`, "block"},
		{"xargs-stdin-file-then-copy", `xargs unzip < list.txt; cp a.txt build/`, "block"},
		{"xargs-replace-then-copy", `ls *.zip | xargs -I{} unzip {}; cp a.txt build/`, "block"},
		{"xargs-sudo-then-copy", `ls *.zip | xargs sudo unzip; cp a.txt build/`, "block"},
		{"xargs-env-then-copy", `ls *.zip | xargs env unzip; cp a.txt build/`, "block"},
		{"xargs-command-then-copy", `ls *.zip | xargs command unzip; cp a.txt build/`, "block"},
		{"xargs-env-S-then-copy", `ls *.zip | xargs env -S unzip; cp a.txt build/`, "block"},
		{"lookup-piped-to-xargs-then-copy", `command -v unzip | xargs unzip; cp a.txt build/`, "block"},
		{"xargs-overwrite-then-copy", `ls *.zip | xargs unzip -o; cp a.txt build/`, "block"},
		// Round 5 (M3): a supplied list mode is a Possible scope, allowed
		// in the default pack with a visible alert-only finding.
		{"xargs-list-then-copy", `ls *.zip | xargs unzip -l; cp a.txt build/`, "alert"},
		{"xargs-lookup", `ls | xargs command -v unzip`, "allow"},
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
		verdict := call.verdict
		if strings.HasPrefix(call.body, `{"action":"alert"`) {
			verdict = "alert"
		}
		if want := rows[i/4].want; verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.300s", call.name, verdict, want, call.body)
		}
		if strings.Contains(call.body, "internal evaluator error") || strings.Contains(call.body, "panics.total") {
			t.Errorf("%s: panic answer: %.300s", call.name, call.body)
		}
	}
}

// TestGAP0055ProgramLookupsAndShortArgvFourCell is the gateway side of the
// GAP-0055 class: each program the hook path reads by name (archive, copy,
// link, rename, directory and multicall programs) behind a lookup is
// allowed, and bare or behind a wrapper with no arguments gets a verdict
// that is not the panic answer, for both connectors, managed and per-user.
// A race build runs the lookups and the bare forms.
func TestGAP0055ProgramLookupsAndShortArgvFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	var programs []string
	for _, list := range [][]string{
		{"rsync", "cpio", "bsdcpio", "pax", "tar", "gtar", "bsdtar", "unzip", "7z", "7za", "7zr", "jar", "ditto"},
		{"cp", "gcp", "ln", "gln", "link", "mv", "gmv", "install", "cd", "pushd", "popd", "busybox", "toybox"},
	} {
		programs = append(programs, list...)
	}
	lookups := []string{"command -v %s", "command -V %s", "command -v %s && command -v tar", "type %s", "hash %s"}
	others := []string{"%s", "env %s", "sudo -n %s", "nice %s", "command %s", "exec -a x %s"}
	if hookAnswerRaceBuild {
		lookups, others = lookups[:1], others[:1]
	}
	type row struct{ name, command, want string }
	var rows []row
	for _, program := range programs {
		for _, form := range lookups {
			rows = append(rows, row{fmt.Sprintf(form, program), fmt.Sprintf(form, program), "allow"})
		}
		for _, form := range others {
			rows = append(rows, row{fmt.Sprintf(form, program), fmt.Sprintf(form, program), ""})
		}
	}
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := make([]*hookCall, 0, 4*len(rows))
	for _, r := range rows {
		payload := f.payload(t, r.command)
		var header string
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("%s: managed hook client panic: %v", r.name, recovered)
				}
			}()
			header = hookpaths.Resolve(payload)
		}()
		calls = append(calls, everyMode(r.name, payload, header)...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		if want := rows[i/4].want; want != "" && call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.300s", call.name, call.verdict, want, call.body)
		}
		if call.verdict != "allow" && call.verdict != "block" {
			t.Errorf("%s: no verdict: %s", call.name, call.verdict)
		}
		if strings.Contains(call.body, "internal evaluator error") || strings.Contains(call.body, "panics.total") {
			t.Errorf("%s: panic answer: %.300s", call.name, call.body)
		}
	}
}
