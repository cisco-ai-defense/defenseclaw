// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
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

func TestGAP0431QuotedTouchIdentityFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
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
	var calls []*hookCall
	for _, row := range rows {
		if row.want == "block" && hookpaths.NoDereferenceTouchSafe(row.command, f.project, f.home) {
			t.Errorf("%s: entry proof marked protected target safe", row.name)
		}
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		facts, decoded := hookpaths.Decode(header)
		if row.want == "block" && (!decoded || facts[hookpaths.ActionDecisionKey] != hookpaths.ProtectedTargetDecision) {
			t.Errorf("%s: client target decision missing", row.name)
		}
		calls = append(calls, everyMode(row.name, payload, header)...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		row := rows[i/4]
		if call.verdict != row.want {
			t.Errorf("%s: got %s, want %s", call.name, call.verdict, row.want)
		}
	}
}
