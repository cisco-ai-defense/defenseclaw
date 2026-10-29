// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// GAP-0949: under macOS /bin/bash 3.2 a plain `. FILE` of a missing or
// unreadable file is a fatal special-builtin error that exits with status 0,
// so the EXIT trap saw success and a hook that had to block answered nothing.
// Every file a rendered shell hook sources goes through `command .`, which
// keeps the failure a status the hook acts on.
func TestShellHooksSourceEveryFileThroughCommand(t *testing.T) {
	plain := regexp.MustCompile(`^\s*(if\s+!\s+)?\.\s+["$]`)
	for _, path := range shellHookTemplatesForTest(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if plain.MatchString(line) {
				t.Errorf("%s:%d sources a file with a plain dot: %q", filepath.Base(path), i+1, strings.TrimSpace(line))
			}
		}
	}
}

// r103 GAP-0093, GAP-0090: every per-user outage sentence that tells the user
// how to resume protection also names `defenseclaw-gateway status`.
func TestShellHookOutageSentencesNameGatewayStatus(t *testing.T) {
	for _, path := range shellHookTemplatesForTest(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "resume protection") && !strings.Contains(line, "defenseclaw-gateway status") {
				t.Errorf("%s:%d names no gateway status: %q", filepath.Base(path), i+1, strings.TrimSpace(line))
			}
		}
	}
}

func shellHookTemplatesForTest(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("hooks", "*.sh"))
	if err != nil || len(paths) < 10 {
		t.Fatalf("hook templates: %v %v", paths, err)
	}
	return paths
}
