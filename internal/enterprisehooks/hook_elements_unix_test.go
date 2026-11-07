// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// GAP-0754: a restore is read from the protected elements, one by one. The
// agent also writes its own settings in the config that holds the hook entry,
// and that write leaves both elements as they were.
func TestProbeHookElementsReadsEachElementOnItsOwn(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	config := filepath.Join(home, ".hermes", "config.yaml")
	script := filepath.Join(home, ".defenseclaw", "hooks", "hermes-hook.sh")
	installedConfig, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	installedScript, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	probe := func(step string, want []string) {
		t.Helper()
		got, err := ProbeHookElements(context.Background(), opts)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if broken := got.Broken(); !slices.Equal(broken, want) {
			t.Fatalf("%s: broken elements = %v, want %v", step, broken, want)
		}
	}
	probe("after the install", nil)

	// The agent changes one of its own settings.
	if err := os.WriteFile(config, append(slices.Clone(installedConfig), "model: another\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	probe("agent setting written", nil)

	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	probe("script deleted", []string{HookElementRuntime})
	if err := os.WriteFile(script, installedScript, 0o700); err != nil {
		t.Fatal(err)
	}
	probe("script put back", nil)

	if err := os.WriteFile(script, append(slices.Clone(installedScript), "# edited\n"...), 0o700); err != nil {
		t.Fatal(err)
	}
	probe("script edited", []string{HookElementRuntime})
	if err := os.WriteFile(script, installedScript, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(config, []byte("model: another\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe("entry removed, setting kept", []string{HookElementEntry})
	if err := os.WriteFile(config, installedConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	probe("entry put back", nil)

	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe("both broken", []string{HookElementRuntime})
	if err := os.WriteFile(script, installedScript, 0o700); err != nil {
		t.Fatal(err)
	}
	probe("script put back, entry still removed", []string{HookElementEntry})
}
