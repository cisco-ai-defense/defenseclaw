// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The discovery cache Python writes names a kiro-cli by its banner and the
// Kiro IDE by a bare version; the hook floors read a bare version as a
// kiro-cli's and the IDE's with KiroIDEVersionSuffix.
func TestKiroDiscoveryCacheVersionMarksTheIDE(t *testing.T) {
	for cached, want := range map[string]string{
		"":                               "",
		"1.0.182":                        "1.0.182" + KiroIDEVersionSuffix,
		" 1.0.150 ":                      "1.0.150" + KiroIDEVersionSuffix,
		"1.0.182" + KiroIDEVersionSuffix: "1.0.182" + KiroIDEVersionSuffix,
		"kiro-cli 2.27.1":                "kiro-cli 2.27.1",
		"Kiro-CLI v2.26.1":               "Kiro-CLI v2.26.1",
		"kiro-cli\t2.30.0":               "kiro-cli\t2.30.0",
	} {
		if got := kiroDiscoveryCacheVersion(cached); got != want {
			t.Errorf("kiroDiscoveryCacheVersion(%q) = %q, want %q", cached, got, want)
		}
	}

	dataDir := t.TempDir()
	writeDiscovery := func(agents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), []byte(`{"version":7,"agents":{`+agents+`}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeDiscovery(`"kiro":{"version":"1.0.182","installed":true},"codex":{"version":"1.0.182","installed":true}`)
	if got := cachedSetupAgentVersion(dataDir, "kiro"); got != "1.0.182"+KiroIDEVersionSuffix {
		t.Fatalf("cached Kiro IDE = %q", got)
	}
	// Only Kiro has two surfaces under one connector. On Windows a Codex
	// discovery cache is not the protected setup evidence used for admission.
	wantCodex := "1.0.182"
	if runtime.GOOS == "windows" {
		wantCodex = ""
	}
	if got := cachedSetupAgentVersion(dataDir, "codex"); got != wantCodex {
		t.Fatalf("cached codex = %q, want %q", got, wantCodex)
	}
	if got := kiroHookFloorRefusal(resolveHookContract("kiro", cachedSetupAgentVersion(dataDir, "kiro"))); got != "" {
		t.Fatalf("a supported cached IDE is refused: %s", got)
	}
}

// Only the IDE marker added to the same build is no agent change.
func TestKiroIDEMarkerAdded(t *testing.T) {
	lock := func(name, raw, contract string) connector.HookContractLockEntry {
		return connector.HookContractLockEntry{Connector: name, RawAgentVersion: raw, ContractID: contract}
	}
	const c = "kiro-hooks"
	ide := KiroIDEVersionSuffix
	for _, tc := range []struct {
		previous, current connector.HookContractLockEntry
		want              bool
	}{
		{lock("kiro", "1.0.182", c), lock("kiro", "1.0.182"+ide, c), true},
		{lock("kiro", "1.0.182"+ide, c), lock("kiro", "1.0.182", c), false},
		{lock("kiro", "1.0.181", c), lock("kiro", "1.0.182"+ide, c), false},
		{lock("kiro", "1.0.182", c), lock("kiro", "1.0.182"+ide, "kiro-ide-windows"), false},
		{lock("kiro", "", c), lock("kiro", ide, c), false},
		{lock("kiro", "1.0.182"+ide, c), lock("kiro", "1.0.182"+ide, c), false},
		{lock("codex", "1.0.182", c), lock("codex", "1.0.182"+ide, c), false},
	} {
		if got := kiroIDEMarkerAdded(tc.previous, tc.current); got != tc.want {
			t.Errorf("kiroIDEMarkerAdded(%+v, %+v) = %t, want %t", tc.previous, tc.current, got, tc.want)
		}
	}
}
