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

// GAP-1815: the unmanaged writer rebuilds a null fail_modes map from the
// flat records when the gateway restarts (GAP-0512), so the refusal says the
// restart repairs it and carries ErrSharedHookSidecarRestartRepairs, which a
// setup that restarts the gateway goes ahead on. A null map the flat
// records cannot rebuild is refused without it.
func TestSharedHookSidecarRefusalLetsARestartRepairANullFailModesMap(t *testing.T) {
	const nullMap = `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":null,"fail_mode_sources":{"codex":"config"}}`
	writeFlat := func(t *testing.T, dataDir, name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dataDir, "hooks", hookConfigSidecarName+"."+name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("corroborating flat records", func(t *testing.T) {
		dataDir := t.TempDir()
		path := writeSidecarFixture(t, dataDir, nullMap)
		writeFlat(t, dataDir, "codex", "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\nFAIL_MODE_SOURCE=config\n")
		writeFlat(t, dataDir, "claudecode", "DEFENSECLAW_CONNECTOR=claudecode\nDEFENSECLAW_FAIL_MODE=closed\n")
		err := SharedHookSidecarRefusal(SetupOpts{DataDir: dataDir})
		if !errors.Is(err, ErrSharedHookSidecarRestartRepairs) || !errors.Is(err, ErrAgentConfigRefusal) ||
			!strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "without --no-restart") {
			t.Fatalf("SharedHookSidecarRefusal = %v; want the restart-repairs refusal naming %s", err, path)
		}
		if after, _ := os.ReadFile(path); string(after) != nullMap {
			t.Fatalf("the check changed the sidecar: %q", after)
		}
	})
	for name, body := range map[string]string{
		// fail_mode_sources names codex, but its flat record is gone.
		"named flat record gone": nullMap,
		// The T10-L5 shape: no flat record proves a fail mode, so the
		// writer refuses it too.
		"T10-L5 shape, no flat records": `{"version":2,"fail_modes":null,"legacy_fail_mode":"open"}`,
	} {
		t.Run("flat records cannot rebuild it: "+name, func(t *testing.T) {
			dataDir := t.TempDir()
			path := writeSidecarFixture(t, dataDir, body)
			err := SharedHookSidecarRefusal(SetupOpts{DataDir: dataDir})
			if errors.Is(err, ErrSharedHookSidecarRestartRepairs) || !errors.Is(err, ErrAgentConfigRefusal) ||
				!strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "flat records cannot rebuild it") {
				t.Fatalf("SharedHookSidecarRefusal = %v; want a plain refusal naming %s", err, path)
			}
		})
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
