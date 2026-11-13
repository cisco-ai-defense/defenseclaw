// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #1442: observability.local.keep_rejected_records is opt-in. A config
// without it, or with it false, compiles to the store off and to the plan
// digest 1.0.9 compiled, whatever rejected_records_max_rows says.
func TestObservabilityV8KeepRejectedRecordsOffByDefaultKeepsTheDigest(t *testing.T) {
	dataDir := t.TempDir()
	compile := func(source string) *ObservabilityV8Plan {
		t.Helper()
		compiled, err := ParseCompileObservabilityV8("config.yaml", []byte(source), ObservabilityV8CompileOptions{DefaultDataDir: dataDir})
		if err != nil {
			t.Fatal(err)
		}
		return compiled.Plan
	}
	base := "config_version: 8\nobservability:\n  local:\n    retention_days: 7\n"
	without := compile(base)
	local := without.Snapshot().Local
	if local.KeepRejectedRecords || local.RejectedRecordsMaxRows != 0 {
		t.Fatalf("default local=%+v, want the store off", local)
	}
	if bytes.Contains(without.EffectiveJSON(), []byte("rejected_records")) {
		t.Fatal("the effective plan of a config without the keys names them; its digest would move")
	}
	for _, extra := range []string{
		"    keep_rejected_records: false\n",
		"    keep_rejected_records: false\n    rejected_records_max_rows: 500\n",
		"    rejected_records_max_rows: 500\n",
	} {
		if got := compile(base + extra); got.Digest() != without.Digest() || got.Snapshot().Local.KeepRejectedRecords {
			t.Fatalf("%q turned the store on or moved the digest", extra)
		}
	}
	on := compile(base + "    keep_rejected_records: true\n")
	if local := on.Snapshot().Local; !local.KeepRejectedRecords || local.RejectedRecordsMaxRows != ObservabilityV8DefaultRejectedRecordsRows {
		t.Fatalf("on local=%+v", local)
	}
	if on.Digest() == without.Digest() {
		t.Fatal("turning the store on did not change the plan digest")
	}
	capped := compile(base + "    keep_rejected_records: true\n    rejected_records_max_rows: 250\n")
	if got := capped.Snapshot().Local.RejectedRecordsMaxRows; got != 250 {
		t.Fatalf("rejected_records_max_rows=%d want 250", got)
	}
}

func TestObservabilityV8RejectedRecordsMaxRowsRange(t *testing.T) {
	keep := true
	for _, value := range []int{-1, 0, ObservabilityV8MinRejectedRecordsRows - 1, ObservabilityV8MaxRejectedRecordsRows + 1} {
		bad := value
		_, err := CompileObservabilityV8(&ObservabilityV8Source{Local: ObservabilityV8LocalSource{
			KeepRejectedRecords: &keep, RejectedRecordsMaxRows: &bad,
		}})
		if err == nil || !strings.Contains(err.Error(), "observability.local.rejected_records_max_rows") {
			t.Fatalf("rejected_records_max_rows %d: error %v, want a range error", value, err)
		}
		// A bad cap is refused even while the store is off, so turning it on
		// later cannot fail on a value saved earlier.
		if _, err := CompileObservabilityV8(&ObservabilityV8Source{Local: ObservabilityV8LocalSource{RejectedRecordsMaxRows: &bad}}); err == nil {
			t.Fatalf("rejected_records_max_rows %d accepted while off", value)
		}
	}
	for _, value := range []int{ObservabilityV8MinRejectedRecordsRows, ObservabilityV8MaxRejectedRecordsRows} {
		good := value
		plan, err := CompileObservabilityV8(&ObservabilityV8Source{Local: ObservabilityV8LocalSource{
			KeepRejectedRecords: &keep, RejectedRecordsMaxRows: &good,
		}})
		if err != nil || plan.Snapshot().Local.RejectedRecordsMaxRows != value {
			t.Fatalf("rejected_records_max_rows %d: %v", value, err)
		}
	}
}

func TestObservabilityV8RejectedRecordsKeysRefuseWrongTypes(t *testing.T) {
	dataDir := t.TempDir()
	for _, source := range []string{
		"config_version: 8\nobservability:\n  local:\n    keep_rejected_records: yes-please\n",
		"config_version: 8\nobservability:\n  local:\n    rejected_records_max_rows: lots\n",
	} {
		if _, err := ParseCompileObservabilityV8("config.yaml", []byte(source), ObservabilityV8CompileOptions{DefaultDataDir: dataDir}); err == nil {
			t.Fatalf("accepted %q", source)
		}
	}
}

// The configs 1.0.8 and 1.0.9 write (testdata/upgrade, also run by
// TestUpgradeFixturesMigrateRollBackAndReUpgrade) compile with the store
// off and without the new keys in the effective plan.
func TestObservabilityV8RejectedRecordsOffForThe108And109UpgradeFixtures(t *testing.T) {
	for _, release := range []string{"1.0.8", "1.0.9"} {
		t.Run(release, func(t *testing.T) {
			home := t.TempDir()
			raw, err := os.ReadFile(filepath.Join("testdata", "upgrade", release, "home", "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.ReplaceAll(string(raw), "@HOME@", filepath.ToSlash(home))
			compiled, err := ParseCompileObservabilityV8("config.yaml", []byte(text), ObservabilityV8CompileOptions{DefaultDataDir: home})
			if err != nil {
				t.Fatal(err)
			}
			if compiled.Plan.Snapshot().Local.KeepRejectedRecords ||
				bytes.Contains(compiled.Plan.EffectiveJSON(), []byte("rejected_records")) {
				t.Fatal("a pre-1.0.10 config turned the rejected-record store on or moved its digest")
			}
		})
	}
}
