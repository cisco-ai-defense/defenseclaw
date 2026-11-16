// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"strings"
	"testing"
)

func TestShellEscapedProtectedNamePastTheOperandBoundBlocksOnTheHookRoutes(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	escaped := `\.\./.\s\s\h/\a\u\t\h\o\r\i\z\e\d_\k\e\y\s`
	for _, row := range []struct{ name, command string }{
		{"below", "echo x " + strings.Repeat("f ", 900) + ">> " + escaped},
		{"above", "echo x " + strings.Repeat("f ", 1024) + ">> " + escaped},
	} {
		t.Run(row.name, func(t *testing.T) {
			payload := f.payload(t, row.command)
			header := f.clientHeader(t, payload)
			for _, call := range everyMode(row.name, payload, header) {
				mode := os.FileMode(0o700)
				if call.managed {
					mode = 0
				}
				if err := os.Chmod(f.homes, mode); err != nil {
					t.Fatal(err)
				}
				call.verdict, call.body = f.serve(call)
				if call.verdict != "block" {
					t.Errorf("%s: %s; body %.200s", call.name, call.verdict, call.body)
				}
			}
			if err := os.Chmod(f.homes, 0o700); err != nil {
				t.Fatal(err)
			}
		})
	}
}
