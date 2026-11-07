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
	scriptElement := hookRuntimeFileElement(script)
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
	probe("script deleted", []string{scriptElement})
	if err := os.WriteFile(script, installedScript, 0o700); err != nil {
		t.Fatal(err)
	}
	probe("script put back", nil)

	if err := os.WriteFile(script, append(slices.Clone(installedScript), "# edited\n"...), 0o700); err != nil {
		t.Fatal(err)
	}
	probe("script edited", []string{scriptElement})
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
	probe("both broken", []string{scriptElement})
	if err := os.WriteFile(script, installedScript, 0o700); err != nil {
		t.Fatal(err)
	}
	probe("script put back, entry still removed", []string{HookElementEntry})
}

// GAP-0754: every hook runtime file is a protected element of its own. A repair
// that puts the hook script back while another runtime file (a record, the
// token, a shared script) stays broken has restored the script, and the probe
// says so; the file still broken is still named.
func TestProbeHookElementsNamesEachBrokenRuntimeFile(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	script := filepath.Join(hooks, "hermes-hook.sh")
	record := filepath.Join(hooks, ".hookcfg.hermes")
	shared := filepath.Join(hooks, ".hookcfg")
	read := func(path string) []byte {
		t.Helper()
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("the installed %s is unavailable: %v", filepath.Base(path), err)
		}
		return body
	}
	installedScript, installedRecord, installedShared := read(script), read(record), read(shared)
	probe := func(step string, want ...string) {
		t.Helper()
		got, err := ProbeHookElements(context.Background(), opts)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if !slices.Equal(got.Broken(), want) {
			t.Fatalf("%s: broken elements = %v, want %v", step, got.Broken(), want)
		}
		for _, name := range want {
			if got.Matches(name) {
				t.Fatalf("%s: %q is broken and also matches", step, name)
			}
		}
	}
	scriptElement, recordElement, sharedElement := hookRuntimeFileElement(script), hookRuntimeFileElement(record), hookRuntimeFileElement(shared)
	write := func(path string, body []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
	}

	// The script is edited and the flat record is gone: both are named.
	write(script, append(slices.Clone(installedScript), "# edited\n"...), 0o700)
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	probe("script edited, record removed", scriptElement, recordElement)
	// The script is put back; the record still is not.
	write(script, installedScript, 0o700)
	probe("script put back, record still removed", recordElement)
	// The record is put back and the script is edited again.
	write(record, installedRecord, 0o600)
	probe("record put back")
	write(script, append(slices.Clone(installedScript), "# edited\n"...), 0o700)
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	probe("both again", scriptElement, recordElement)
	write(record, installedRecord, 0o600)
	probe("record put back, script still edited", scriptElement)
	write(script, installedScript, 0o700)

	// The shared record is its own element.
	write(shared, []byte("{}\n"), 0o600)
	probe("shared record rewritten", sharedElement)
	write(script, append(slices.Clone(installedScript), "# edited\n"...), 0o700)
	probe("script edited, shared record rewritten", scriptElement, sharedElement)
	write(script, installedScript, 0o700)
	probe("script put back, shared record still rewritten", sharedElement)
	write(shared, installedShared, 0o600)
	probe("everything put back")
}
