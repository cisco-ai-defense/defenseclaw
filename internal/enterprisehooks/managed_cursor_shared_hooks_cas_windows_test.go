// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// hooks.json is shared: administrators and Cursor save it without the
// DefenseClaw lock. Every DefenseClaw write of it, and every undo of such a
// write, must keep a save another writer made after DefenseClaw read the
// file: the rebuild's rollback, target publication (with and without
// enrolled accounts), the empty-enrollment install and the teardown.

// addWindowsCursorAdminHookForTest is an administrator's save: it reads
// hooks.json as it is now, adds one hook and rewrites the file in place.
func addWindowsCursorAdminHookForTest(t *testing.T, path, command string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("administrator fixture: hooks.json is not JSON: %v\n%s", err, data)
	}
	events, _ := document["hooks"].(map[string]any)
	if events == nil {
		events = map[string]any{}
		document["hooks"] = events
	}
	events[command] = []any{map[string]any{"type": "command", "command": command}}
	edited, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
}

// saveBeforeWindowsCursorHooksWriteForTest runs save once, just before
// DefenseClaw replaces hooks.json, whichever writer it uses.
func saveBeforeWindowsCursorHooksWriteForTest(t *testing.T, hooksPath string, save func()) {
	t.Helper()
	done := false
	once := func(path string) {
		if !done && strings.EqualFold(path, hooksPath) {
			done = true
			save()
		}
	}
	previousWriter, previousSwap := windowsManagedPolicyWriter, windowsCursorManagedFileSwap
	windowsManagedPolicyWriter = func(path string, data []byte, userReadable bool) error {
		once(path)
		return previousWriter(path, data, userReadable)
	}
	windowsCursorManagedFileSwap = func(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
		once(request.path)
		return previousSwap(request)
	}
	t.Cleanup(func() { windowsManagedPolicyWriter, windowsCursorManagedFileSwap = previousWriter, previousSwap })
}

// withWindowsCursorStandaloneSeamsForTest points the Cursor machine policy at
// a temporary root on a standalone host, as
// installWindowsCursorStandaloneGuardForTest does, without installing it.
func withWindowsCursorStandaloneSeamsForTest(t *testing.T) windowsCursorPaths {
	t.Helper()
	previousRoot, previousOwner := windowsCursorManagedRootResolver, windowsManagedPolicyOwnerSID
	previousStandalone, previousWriter := windowsEnterpriseStandaloneProcess, windowsManagedPolicyWriter
	previousIdentity, previousHookTrust := windowsEnterpriseMutationIdentityCheck, windowsEnterpriseHookTrustCheck
	previousAncestorTrust, previousDirTrust, previousFileTrust := windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck
	root := filepath.Join(t.TempDir(), "Cursor")
	windowsCursorManagedRootResolver = func() (string, error) { return root, nil }
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) {
		return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	}
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		windowsCursorManagedRootResolver, windowsManagedPolicyOwnerSID = previousRoot, previousOwner
		windowsEnterpriseStandaloneProcess, windowsManagedPolicyWriter = previousStandalone, previousWriter
		windowsEnterpriseMutationIdentityCheck, windowsEnterpriseHookTrustCheck = previousIdentity, previousHookTrust
		windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck = previousAncestorTrust, previousDirTrust, previousFileTrust
	})
	t.Setenv(connector.WindowsGatewayServiceNameEnv, "DefenseClawGateway")
	// The administrator's folder, protected as the install expects it.
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsManagedPolicyProtection(root, true, true); err != nil {
		t.Fatal(err)
	}
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func requireWindowsCursorHooksContainForTest(t *testing.T, path string, commands ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if !bytes.Contains(data, []byte(`"`+command+`"`)) {
			t.Fatalf("hooks.json lost the administrator's save %q:\n%s", command, data)
		}
	}
	return data
}

const windowsCursorSharedHooksTestHook = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`

// A rebuild that loses a race undoes its hooks.json write. The undo must put
// the preimage back only while the file holds the rebuild's bytes, in one
// compare-and-swap: it must never replace a newer save and then try to put
// that save back, which loses a save C made between the two swaps.
func TestWindowsCursorMachineGuardRebuildUndoNeverReplacesANewerSave(t *testing.T) {
	hook := windowsCursorSharedHooksTestHook
	for _, enrolled := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "Alice"}[enrolled], func(t *testing.T) {
			paths := installWindowsCursorStandaloneGuardForTest(t, hook, enrolled)
			addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-original")
			current, err := os.ReadFile(paths.Hooks)
			if err != nil {
				t.Fatal(err)
			}
			// Damage: the registration is gone, the administrator's hook stays.
			preimage, err := connector.RemoveWindowsCursorEnterpriseHooks(current, paths.Adapter)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(paths.Hooks, preimage, 0o600); err != nil {
				t.Fatal(err)
			}
			wroteRebuild, wrotePutBack := false, false
			previousSwap := windowsCursorManagedFileSwap
			windowsCursorManagedFileSwap = func(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
				result, err := previousSwap(request)
				if strings.EqualFold(request.path, paths.Hooks) {
					switch {
					case !wroteRebuild && !bytes.Equal(request.data, preimage):
						// B: saved over the rebuilt file before it is
						// validated, without the registration, so the
						// rebuild rolls back.
						wroteRebuild = true
						saveWindowsCursorHooksWithoutGuardForTest(t, paths, "admin-save-b")
					case wroteRebuild && !wrotePutBack && bytes.Equal(request.data, preimage):
						// C: saved right after the undo's swap of the preimage.
						wrotePutBack = true
						addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-save-c")
					}
				}
				return result, err
			}
			t.Cleanup(func() { windowsCursorManagedFileSwap = previousSwap })
			if _, err := RestoreWindowsCursorManagedAdapter(hook); err != nil {
				t.Fatalf("rebuild: %v", err)
			}
			if !wroteRebuild || !wrotePutBack {
				t.Fatalf("fixture: the rebuild did not race (rebuild save %t, put-back save %t)", wroteRebuild, wrotePutBack)
			}
			windowsCursorManagedFileSwap = previousSwap
			if _, err := RestoreWindowsCursorManagedAdapter(hook); err != nil {
				t.Fatalf("quiet repair: %v", err)
			}
			after := requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-save-c")
			if err := connector.VerifyWindowsCursorEnterpriseHooks(after, paths.Adapter, "closed"); err != nil {
				t.Fatalf("the repaired registration is not the closed guard: %v", err)
			}
			if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
				t.Fatalf("repaired guard: active=%t err=%v", active, err)
			}
		})
	}
}

// Publication repairs an unreadable hooks.json when Alice's enrollment is
// revoked. An administrator's save between DefenseClaw's read and its write
// must be kept, with the closed registration merged in.
// (Publication with remaining targets runs the same write; its fixture needs
// real user profiles.)
func TestWindowsCursorTargetPublicationKeepsAConcurrentHooksSave(t *testing.T) {
	hook := windowsCursorSharedHooksTestHook
	alice := WindowsCursorManagedRuntimeTarget{SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\alice\.defenseclaw`}
	for _, publish := range []struct {
		name    string
		targets []WindowsCursorManagedRuntimeTarget
		mode    string
	}{
		{name: "zero targets", targets: []WindowsCursorManagedRuntimeTarget{}, mode: "closed"},
	} {
		t.Run(publish.name, func(t *testing.T) {
			paths := installWindowsCursorStandaloneGuardForTest(t, hook, false)
			addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-original")
			// Enroll Alice with an open target mode; the host guard stays closed.
			data, err := os.ReadFile(paths.State)
			if err != nil {
				t.Fatal(err)
			}
			var state windowsCursorManagedPolicyState
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatal(err)
			}
			state.Targets = []WindowsCursorManagedRuntimeTarget{alice}
			state.TargetFailModes = map[string]string{alice.SID: "open"}
			state.HookFailMode = "open"
			adapter, err := renderWindowsCursorManagedAdapter(state)
			if err != nil {
				t.Fatal(err)
			}
			state.AdapterSHA256 = windowsManagedPolicyDigest(adapter)
			body, err := windowsCursorManagedStateBody(state)
			if err != nil {
				t.Fatal(err)
			}
			hooks, err := os.ReadFile(paths.Hooks)
			if err != nil {
				t.Fatal(err)
			}
			if hooks, err = connector.MergeWindowsCursorEnterpriseHooks(hooks, paths.Adapter, cursorMachineHookFlagMode(state.HookFailMode)); err != nil {
				t.Fatal(err)
			}
			for path, content := range map[string][]byte{paths.Adapter: adapter, paths.State: body, paths.Hooks: hooks} {
				if err := windowsManagedPolicyWriter(path, content, true); err != nil {
					t.Fatal(err)
				}
			}
			protectWindowsCursorHooksForAdminsForTest(t, paths.Hooks)
			if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
				t.Fatalf("fixture guard: active=%t err=%v", active, err)
			}
			saveBeforeWindowsCursorHooksWriteForTest(t, paths.Hooks, func() {
				addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-concurrent")
			})
			if err := PublishWindowsCursorManagedPolicyTargets(publish.targets); err != nil {
				t.Fatalf("publication: %v", err)
			}
			after := requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-concurrent")
			if err := connector.VerifyWindowsCursorEnterpriseHooks(after, paths.Adapter, publish.mode); err != nil {
				t.Fatalf("the published registration is not %s: %v", publish.mode, err)
			}
			targets, active, err := ReadWindowsCursorManagedPolicyTargets()
			if err != nil || !active || len(targets) != len(publish.targets) {
				t.Fatalf("published guard: active=%t targets=%v err=%v", active, targets, err)
			}
		})
	}
}

// The empty-enrollment install merges the closed guard into an
// administrator's existing hooks.json and records that file as the original
// configuration. A save between DefenseClaw's read and its write must be
// kept, and the receipt must record the saved file, so that the teardown
// gives the administrator back exactly that file.
func TestWindowsCursorEmptyEnrollmentInstallKeepsAConcurrentHooksSave(t *testing.T) {
	paths := withWindowsCursorStandaloneSeamsForTest(t)
	original := []byte(`{"version":1,"hooks":{"admin-original":[{"type":"command","command":"admin-original"}]}}`)
	if err := os.WriteFile(paths.Hooks, original, 0o600); err != nil {
		t.Fatal(err)
	}
	saveBeforeWindowsCursorHooksWriteForTest(t, paths.Hooks, func() {
		addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-concurrent")
	})
	if err := EnsureWindowsStandaloneCursorManagedPolicy(connector.SetupOpts{
		APIAddr: "127.0.0.1:18970", HookExecutable: windowsCursorSharedHooksTestHook,
	}); err != nil {
		t.Fatalf("install: %v", err)
	}
	after := requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-concurrent")
	if err := connector.VerifyWindowsCursorEnterpriseHooks(after, paths.Adapter, "closed"); err != nil {
		t.Fatalf("the installed registration is not the closed guard: %v", err)
	}
	targets, active, err := ReadWindowsCursorManagedPolicyTargets()
	if err != nil || !active || len(targets) != 0 {
		t.Fatalf("installed guard: active=%t targets=%v err=%v", active, targets, err)
	}
	saved, err := connector.RemoveWindowsCursorEnterpriseHooks(after, paths.Adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := DeactivateWindowsCursorManagedPolicy(); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	restored := requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-concurrent")
	if !connector.WindowsCursorEnterpriseHooksOwnedRemainderEqual(restored, saved) {
		t.Fatalf("the teardown did not give back the administrator's saved file:\n%s\nwant\n%s", restored, saved)
	}
}

// The teardown removes DefenseClaw's entries from hooks.json. An
// administrator's save between DefenseClaw's read and its write must be kept,
// without DefenseClaw's entries.
func TestWindowsCursorTeardownKeepsAConcurrentHooksSave(t *testing.T) {
	paths := withWindowsCursorStandaloneSeamsForTest(t)
	original := []byte(`{"version":1,"hooks":{"admin-original":[{"type":"command","command":"admin-original"}]}}`)
	if err := os.WriteFile(paths.Hooks, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureWindowsStandaloneCursorManagedPolicy(connector.SetupOpts{
		APIAddr: "127.0.0.1:18970", HookExecutable: windowsCursorSharedHooksTestHook,
	}); err != nil {
		t.Fatalf("install: %v", err)
	}
	saveBeforeWindowsCursorHooksWriteForTest(t, paths.Hooks, func() {
		addWindowsCursorAdminHookForTest(t, paths.Hooks, "admin-concurrent")
	})
	if err := DeactivateWindowsCursorManagedPolicy(); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	after := requireWindowsCursorHooksContainForTest(t, paths.Hooks, "admin-original", "admin-concurrent")
	if cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(after, paths.Adapter); err != nil || !bytes.Equal(cleaned, after) {
		t.Fatalf("the teardown left DefenseClaw entries in hooks.json (err %v):\n%s", err, after)
	}
	if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || active {
		t.Fatalf("after teardown: active=%t err=%v", active, err)
	}
}
