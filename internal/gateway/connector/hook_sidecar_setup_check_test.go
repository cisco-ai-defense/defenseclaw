// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1325: `defenseclaw setup claude-code` saved its change and reported
// success while the shared hook config was malformed (the T10-L5 fixture,
// fail_modes null). The check setup runs first now refuses it with the file
// and the fix, changes nothing, and passes a sidecar a writer carries.
func TestSharedHookSidecarRefusalNamesMalformedSidecar(t *testing.T) {
	malformed := map[string]string{
		"fail_modes null (T10-L5)": `{"version":2,"fail_modes":null,"legacy_fail_mode":"open"}`,
		"not JSON":                 `{"version":2,`,
		"fail_modes not an object": `{"version":2,"fail_modes":"open"}`,
		"version as a string":      `{"version":"2","fail_modes":{}}`,
		"duplicate key":            `{"version":2,"fail_modes":{},"fail_modes":{}}`,
		"backslash escape":         `{"version":2,"fail_modes":{"claudecode":"\u006fpen"}}`,
	}
	for name, body := range malformed {
		t.Run(name, func(t *testing.T) {
			dataDir := t.TempDir()
			path := writeSidecarFixture(t, dataDir, body)
			err := SharedHookSidecarRefusal(SetupOpts{DataDir: dataDir})
			if !errors.Is(err, ErrAgentConfigRefusal) || !strings.Contains(err.Error(), path) ||
				!strings.Contains(err.Error(), "defenseclaw-gateway restart") {
				t.Fatalf("SharedHookSidecarRefusal = %v; want a refusal naming %s and the fix", err, path)
			}
			if after, _ := os.ReadFile(path); string(after) != body {
				t.Fatalf("the check changed the sidecar: %q", after)
			}
			if err := SharedHookSidecarRefusal(SetupOpts{DataDir: dataDir, ManagedEnterprise: true}); err != nil {
				t.Fatalf("managed: %v; the guardian owns a managed sidecar", err)
			}
		})
	}
	for name, body := range map[string]string{
		"v2 map":        `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"claudecode":"closed","codex":"open"},"fail_mode_sources":{"codex":"config"}}`,
		"legacy scalar": "DEFENSECLAW_FAIL_MODE=closed\n",
	} {
		t.Run("carryable "+name, func(t *testing.T) {
			dataDir := t.TempDir()
			writeSidecarFixture(t, dataDir, body)
			if err := SharedHookSidecarRefusal(SetupOpts{DataDir: dataDir}); err != nil {
				t.Fatalf("SharedHookSidecarRefusal(%s) = %v", name, err)
			}
		})
	}
	if err := SharedHookSidecarRefusal(SetupOpts{DataDir: t.TempDir()}); err != nil {
		t.Fatalf("absent sidecar: %v", err)
	}
}

func writeSidecarFixture(t *testing.T, dataDir, body string) string {
	t.Helper()
	path := filepath.Join(dataDir, "hooks", hookConfigSidecarName)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
