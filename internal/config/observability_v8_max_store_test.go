// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// #1384: observability.local.max_store_mb is an opt-in size cap. The local
// blocks 1.0.2, 1.0.3, 1.0.4 and 1.0.5 write (path and judge_bodies_path,
// and retention_days when the operator set it) compile to no cap and to the
// effective plan those releases compiled, so the plan digest an upgrade
// stamps on every record does not move.
func TestObservabilityV8MaxStoreMBOffForEarlierReleaseConfigs(t *testing.T) {
	dataDir := t.TempDir()
	audit := filepath.ToSlash(filepath.Join(dataDir, "audit.db"))
	judge := filepath.ToSlash(filepath.Join(dataDir, "judge_bodies.db"))
	written := "config_version: 8\nobservability:\n  local:\n    path: " + audit + "\n    judge_bodies_path: " + judge + "\n"
	for _, tc := range []struct{ release, source string }{
		{"1.0.2", written},
		{"1.0.3", written},
		{"1.0.4", written + "    retention_days: 30\n"},
		{"1.0.5", written + "    retention_days: 0\n"},
		{"defaults", "config_version: 8\nobservability: {}\n"},
	} {
		t.Run(tc.release, func(t *testing.T) {
			compiled, err := ParseCompileObservabilityV8("config.yaml", []byte(tc.source),
				ObservabilityV8CompileOptions{DefaultDataDir: dataDir})
			if err != nil {
				t.Fatal(err)
			}
			plan := compiled.Plan
			if got := plan.Snapshot().Local.MaxStoreMB; got != 0 {
				t.Fatalf("max_store_mb = %d, want 0 (off)", got)
			}
			if bytes.Contains(plan.EffectiveJSON(), []byte("max_store_mb")) {
				t.Fatal("the effective plan of a config without the key names max_store_mb; its digest would move")
			}
		})
	}
}

func TestObservabilityV8MaxStoreMBDigestUnchangedByZero(t *testing.T) {
	dataDir := t.TempDir()
	base := "config_version: 8\nobservability:\n  local:\n    retention_days: 7\n"
	without, err := ParseCompileObservabilityV8("config.yaml", []byte(base), ObservabilityV8CompileOptions{DefaultDataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := ParseCompileObservabilityV8("config.yaml", []byte(base+"    max_store_mb: 0\n"),
		ObservabilityV8CompileOptions{DefaultDataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if without.Plan.Digest() != zero.Plan.Digest() {
		t.Fatal("max_store_mb: 0 changed the plan digest")
	}
	capped, err := ParseCompileObservabilityV8("config.yaml", []byte(base+"    max_store_mb: 2048\n"),
		ObservabilityV8CompileOptions{DefaultDataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if got := capped.Plan.Snapshot().Local.MaxStoreMB; got != 2048 {
		t.Fatalf("max_store_mb = %d, want 2048", got)
	}
	if capped.Plan.Digest() == without.Plan.Digest() {
		t.Fatal("a size cap did not change the plan digest")
	}
}

func TestObservabilityV8MaxStoreMBRange(t *testing.T) {
	for _, value := range []int{-1, 1, 63, ObservabilityV8MaxStoreMB + 1} {
		bad := value
		_, err := CompileObservabilityV8(&ObservabilityV8Source{Local: ObservabilityV8LocalSource{MaxStoreMB: &bad}})
		if err == nil || !strings.Contains(err.Error(), "observability.local.max_store_mb") {
			t.Fatalf("max_store_mb %d: error %v, want a range error", value, err)
		}
	}
	for _, value := range []int{0, ObservabilityV8MinStoreMB, ObservabilityV8MaxStoreMB} {
		good := value
		plan, err := CompileObservabilityV8(&ObservabilityV8Source{Local: ObservabilityV8LocalSource{MaxStoreMB: &good}})
		if err != nil {
			t.Fatalf("max_store_mb %d: %v", value, err)
		}
		if got := plan.Snapshot().Local.MaxStoreMB; got != value {
			t.Fatalf("max_store_mb = %d, want %d", got, value)
		}
	}
}
