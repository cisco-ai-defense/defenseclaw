// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const cursorRepairForeignHooks = `{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`

type cursorRepairFixture struct {
	paths   windowsCursorPaths
	state   windowsCursorManagedPolicyState
	adapter []byte
	receipt []byte
	opts    WindowsCursorManagedPolicyTeardownOptions
}

// newCursorRepairFixture writes an installed Cursor policy (state, adapter,
// receipt) under a temporary Cursor root and returns it with hooks.json
// holding only an operator's entry.
func newCursorRepairFixture(t *testing.T, failMode string) cursorRepairFixture {
	t.Helper()
	originalTrust := windowsManagedPolicyFileTrustCheck
	originalRoot := windowsCursorManagedRootResolver
	originalWriter := windowsManagedPolicyWriter
	root := filepath.Join(t.TempDir(), "Cursor")
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsCursorManagedRootResolver = func() (string, error) { return root, nil }
	windowsManagedPolicyWriter = writeWindowsManagedFile
	t.Cleanup(func() {
		windowsManagedPolicyFileTrustCheck = originalTrust
		windowsCursorManagedRootResolver = originalRoot
		windowsManagedPolicyWriter = originalWriter
	})
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	state := windowsCursorManagedPolicyState{
		SchemaVersion:      1,
		HookExecutable:     `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		HookFailMode:       failMode,
		Targets: []WindowsCursorManagedRuntimeTarget{{
			SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\developer\.defenseclaw`,
		}},
	}
	adapter, err := renderWindowsCursorManagedAdapter(state)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := windowsCursorManagedReceiptBody(windowsCursorManagedPolicyReceipt{SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	state.AdapterSHA256 = windowsManagedPolicyDigest(adapter)
	state.ReceiptSHA256 = windowsManagedPolicyDigest(receipt)
	body, err := windowsCursorManagedStateBody(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		paths.Hooks:   []byte(cursorRepairForeignHooks),
		paths.Adapter: adapter,
		paths.State:   body,
		paths.Receipt: receipt,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cursorRepairFixture{
		paths:   paths,
		state:   state,
		adapter: adapter,
		receipt: receipt,
		opts: WindowsCursorManagedPolicyTeardownOptions{
			HookExecutable:     state.HookExecutable,
			GatewayAddr:        state.GatewayAddr,
			GatewayServiceName: state.GatewayServiceName,
		},
	}
}

func readCursorRepairHooks(t *testing.T, f cursorRepairFixture) []byte {
	t.Helper()
	data, err := os.ReadFile(f.paths.Hooks)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRepairWindowsCursorManagedRegistrationRestoresRemovedEntries(t *testing.T) {
	for _, failMode := range []string{"open", "closed", ""} {
		t.Run("mode="+failMode, func(t *testing.T) {
			f := newCursorRepairFixture(t, failMode)
			repaired, err := repairWindowsCursorManagedRegistrationUnlocked(f.opts)
			if err != nil || !repaired {
				t.Fatalf("repaired=%t err=%v, want the registration restored", repaired, err)
			}
			hooks := readCursorRepairHooks(t, f)
			if err := connector.VerifyWindowsCursorEnterpriseHooks(hooks, f.paths.Adapter, cursorManagedPolicyFailMode(f.state)); err != nil {
				t.Fatalf("restored hooks.json does not verify with the recorded fail mode: %v", err)
			}
			if !bytes.Contains(hooks, []byte("operator-hook")) {
				t.Fatal("restore dropped the operator's hooks.json entry")
			}
			targets, active, err := ReadWindowsCursorManagedPolicyTargets()
			if err != nil || !active || len(targets) != 1 {
				t.Fatalf("policy after restore: targets=%v active=%t err=%v", targets, active, err)
			}
			if repaired, err := repairWindowsCursorManagedRegistrationUnlocked(f.opts); err != nil || repaired {
				t.Fatalf("second repair: repaired=%t err=%v, want nothing to do", repaired, err)
			}
		})
	}
}

func TestRepairWindowsCursorManagedRegistrationWritesNothingItCannotAuthenticate(t *testing.T) {
	for _, test := range []struct {
		name   string
		damage func(t *testing.T, f *cursorRepairFixture)
	}{
		{name: "another hook executable", damage: func(t *testing.T, f *cursorRepairFixture) {
			f.opts.HookExecutable = `C:\Other\bin\defenseclaw-hook.exe`
		}},
		{name: "another gateway service", damage: func(t *testing.T, f *cursorRepairFixture) {
			f.opts.GatewayServiceName = "OtherGateway"
		}},
		{name: "another gateway address", damage: func(t *testing.T, f *cursorRepairFixture) {
			f.opts.GatewayAddr = "127.0.0.1:18971"
		}},
		{name: "hooks.json is not JSON", damage: func(t *testing.T, f *cursorRepairFixture) {
			writeCursorRepairFile(t, f.paths.Hooks, []byte(`{"hooks":`))
		}},
		{name: "hooks.json of another version", damage: func(t *testing.T, f *cursorRepairFixture) {
			writeCursorRepairFile(t, f.paths.Hooks, []byte(`{"version":2,"hooks":{}}`))
		}},
		{name: "adapter changed", damage: func(t *testing.T, f *cursorRepairFixture) {
			writeCursorRepairFile(t, f.paths.Adapter, append(append([]byte(nil), f.adapter...), []byte("\n# changed")...))
		}},
		{name: "receipt changed", damage: func(t *testing.T, f *cursorRepairFixture) {
			writeCursorRepairFile(t, f.paths.Receipt, append(append([]byte(nil), f.receipt...), ' '))
		}},
		{name: "receipt missing", damage: func(t *testing.T, f *cursorRepairFixture) {
			if err := os.Remove(f.paths.Receipt); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "strict ancestor trust", damage: func(t *testing.T, f *cursorRepairFixture) {
			t.Setenv(managed.TrustStrictAncestorsEnv, "1")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCursorRepairFixture(t, "open")
			test.damage(t, &f)
			before := readCursorRepairHooks(t, f)
			repaired, err := repairWindowsCursorManagedRegistrationUnlocked(f.opts)
			if err != nil || repaired {
				t.Fatalf("repaired=%t err=%v, want a refusal that writes nothing", repaired, err)
			}
			if after := readCursorRepairHooks(t, f); !bytes.Equal(after, before) {
				t.Fatalf("refused repair changed hooks.json:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

func TestRepairWindowsCursorManagedRegistrationLeavesIntactPolicy(t *testing.T) {
	f := newCursorRepairFixture(t, "open")
	intact, err := connector.MergeWindowsCursorEnterpriseHooks([]byte(cursorRepairForeignHooks), f.paths.Adapter, "open")
	if err != nil {
		t.Fatal(err)
	}
	writeCursorRepairFile(t, f.paths.Hooks, intact)
	if repaired, err := repairWindowsCursorManagedRegistrationUnlocked(f.opts); err != nil || repaired {
		t.Fatalf("repaired=%t err=%v, want an intact registration left alone", repaired, err)
	}
	if after := readCursorRepairHooks(t, f); !bytes.Equal(after, intact) {
		t.Fatal("an intact hooks.json was rewritten")
	}
}

func writeCursorRepairFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
