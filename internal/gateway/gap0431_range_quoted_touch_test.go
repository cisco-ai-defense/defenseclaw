// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP0431PaddedRangeStepAndWidthFourCell(t *testing.T) {
	rows := []struct{ name, link, command, want string }{
		{"reverse-positive-step-odd", "0151", `touch {0300..0001..2}`, "allow"},
		{"ascending-negative-step-even", "0150", `touch {0001..0300..-2}`, "allow"},
		{"reverse-positive-step-even", "0150", `touch {0300..0001..2}`, "block"},
		{"cross-zero-positive", "00148", `touch -- {-0150..0150}`, "block"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			if err := os.Symlink(f.keys, filepath.Join(f.project, row.link)); err != nil {
				t.Fatal(err)
			}
			payload := f.payload(t, row.command)
			calls := everyMode(row.name, payload, f.clientHeader(t, payload))
			f.answerAll(t, calls)
			for _, call := range calls {
				if call.verdict != row.want {
					t.Errorf("%s: got %s, want %s", call.name, call.verdict, row.want)
				}
			}
		})
	}
}

func TestGAP0431SignedStepRangeFourCell(t *testing.T) {
	rows := []struct{ name, link, command, want string }{
		{"ascending-skipped-name", "1", `touch {-0..+005..-2}`, "allow"},
		{"ascending-member", "2", `touch {-0..+005..-2}`, "block"},
		{"descending-skipped-name", "2", `touch {+005..-0..2}`, "allow"},
		{"descending-member", "3", `touch {+005..-0..2}`, "block"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			if err := os.Symlink(f.keys, filepath.Join(f.project, row.link)); err != nil {
				t.Fatal(err)
			}
			payload := f.payload(t, row.command)
			calls := everyMode(row.name, payload, f.clientHeader(t, payload))
			f.answerAll(t, calls)
			for _, call := range calls {
				if call.verdict != row.want {
					t.Errorf("%s: got %s, want %s", call.name, call.verdict, row.want)
				}
			}
		})
	}
}

func TestGAP0431QuotedTouchIdentityFourCell(t *testing.T) {
	runGAP0431QuotedTouchIdentity(t, newB36ManagedHookFixture(t), true, true)
}

// The same rows without -h: touch follows a link, and the target scan, not
// the entry proof, reads each name. A quoted or escaped bracket is part of
// the name, so the hard link is the protected file (GAP-0293: it was never
// resolved, in any environment).
func TestGAP0293QuotedTouchFollowIdentityFourCell(t *testing.T) {
	runGAP0431QuotedTouchIdentity(t, newB36ManagedHookFixture(t), true, false)
}

// The hook reads the shell startup from the account's environment. An
// exported function the touch statement never calls (RHEL exports which, the
// shared dev host exports its own helpers) must leave every reading as it is,
// and a startup that can change what runs (a startup file or a function that
// replaces touch) may only withhold the safe proof: each protected hard link
// still blocks (GAP-0293: it was allowed on a host whose profile exported a
// function).
func TestGAP0431QuotedTouchIdentityShellStartupFourCell(t *testing.T) {
	for _, tc := range []struct {
		name, variable string
		startupFile    bool
		exact          bool
	}{
		{name: "unrelated-exported-function", variable: "BASH_FUNC_s7probe%%", exact: true},
		{name: "unrelated-patched-export", variable: "BASH_FUNC_s7probe()", exact: true},
		{name: "exported-touch-function", variable: "BASH_FUNC_touch%%"},
		{name: "exported-path-touch-function", variable: "BASH_FUNC_/usr/bin/touch%%"},
		{name: "startup-file", variable: "BASH_ENV", startupFile: true},
	} {
		for _, noDereference := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/no-dereference=%t", tc.name, noDereference), func(t *testing.T) {
				f := newB36ManagedHookFixture(t)
				value := "() {  :\n}"
				if tc.startupFile {
					value = filepath.Join(f.home, "startup.sh")
					if err := os.WriteFile(value, []byte(":\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv(tc.variable, value)
				runGAP0431QuotedTouchIdentity(t, f, tc.exact, noDereference)
			})
		}
	}
}

// runGAP0431QuotedTouchIdentity runs the quoted touch identity rows in all
// four cells. Every protected row must block; exact also holds each ordinary
// row to allow. Without noDereference the rows drop -h: the quoted symlink
// row then touches the keys file through the link and blocks.
func runGAP0431QuotedTouchIdentity(t *testing.T, f b36ManagedHookFixture, exact, noDereference bool) {
	t.Helper()
	if err := os.Link(f.keys, filepath.Join(f.project, "alias[1]")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "alias1"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.keys, filepath.Join(f.project, "link[1]")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "link1"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "ordinary[1]"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(f.keys, filepath.Join(f.project, "ordinary1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(f.keys, filepath.Join(f.project, "mix[1]suffix")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "mix1suffix"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "normal[1]suffix"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(f.keys, filepath.Join(f.project, "normal1suffix")); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command, want string }{
		{"single-quoted-hardlink", `touch -h 'alias[1]'`, "block"},
		{"double-quoted-hardlink", `touch -h "alias[1]"`, "block"},
		{"escaped-hardlink", `touch -h alias\[1\]`, "block"},
		{"assigned-quoted-hardlink", `p='alias[1]'; touch -h "$p"`, "block"},
		{"quoted-ordinary", `touch -h 'ordinary[1]'`, "allow"},
		{"unquoted-protected-glob", `touch -h ordinary[1]`, "block"},
		{"quoted-symlink", `touch -h 'link[1]'`, "allow"},
		{"unquoted-ordinary-glob", `touch -h alias[1]`, "allow"},
		{"ordinary-control", `touch -h alias1`, "allow"},
		{"quoted-prefix-hardlink", `touch -h 'mix[1]'*`, "block"},
		{"escaped-prefix-hardlink", `touch -h mix\[1\]*`, "block"},
		{"quoted-prefix-ordinary", `touch -h 'normal[1]'*`, "allow"},
		{"escaped-prefix-ordinary", `touch -h normal\[1\]*`, "allow"},
	}
	if !noDereference {
		for i := range rows {
			rows[i].name += "/follow"
			rows[i].command = strings.Replace(rows[i].command, "touch -h ", "touch ", 1)
			if strings.HasPrefix(rows[i].name, "quoted-symlink") {
				rows[i].want = "block"
			}
		}
	}
	var calls []*hookCall
	for _, row := range rows {
		if noDereference && row.want == "block" && hookpaths.NoDereferenceTouchSafe(row.command, f.project, f.home) {
			t.Errorf("%s: entry proof marked protected target safe", row.name)
		}
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		facts, decoded := hookpaths.Decode(header)
		if noDereference && row.want == "block" && (!decoded || facts[hookpaths.ActionDecisionKey] != hookpaths.ProtectedTargetDecision) {
			t.Errorf("%s: client target decision missing", row.name)
		}
		calls = append(calls, everyMode(row.name, payload, header)...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		row := rows[i/4]
		if call.verdict != row.want && (exact || row.want == "block") {
			t.Errorf("%s: got %s, want %s", call.name, call.verdict, row.want)
		}
	}
}
