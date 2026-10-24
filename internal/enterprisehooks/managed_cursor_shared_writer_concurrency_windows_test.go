// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile/sharedfiletest"
)

// Every DefenseClaw write, rollback and restore of the shared
// C:\ProgramData\Cursor\hooks.json goes through one writer
// (windowsCursorHooksWriter). This is the concurrency harness for all of
// them: for each operation (setup, publication, repair, teardown, restore,
// and the rollback of each), an administrator changes hooks.json (its bytes,
// its access list or an attribute) just before DefenseClaw's first write of
// it, or just after it. The change must be kept, the operation must end with
// the guard it promises, and a reader that watches the files throughout must
// never see the machine policy without its hook: no DefenseClaw registration
// in hooks.json while the adapter it names is missing or the allow-only
// tombstone, and no moment without a hooks.json that exists before and after.

type cursorSharedWriterOp struct {
	name string
	// prepare builds the guard and the administrator's hooks.json and returns
	// the DefenseClaw operation.
	prepare func(t *testing.T) (windowsCursorPaths, func() error)
	// fail makes DefenseClaw's first hooks.json publication fail right after
	// it lands, so the operation rolls back.
	fail    bool
	wantErr bool
	// anyErr: the operation may stop with an error or finish; a rebuild whose
	// rollback met a newer save starts again from it.
	anyErr bool
	// want is the guard the operation ends with: "closed", "open" or
	// "inactive"; repair, when set, runs before the check (a quiet repair
	// after a stopped one).
	want   string
	repair bool
	// steady: the registration must be in hooks.json at every moment.
	steady bool
	// absent: hooks.json is missing when the operation starts.
	absent bool
}

const windowsCursorSharedWriterAdminCommand = "admin-concurrent"

func windowsCursorSharedWriterAdmin(paths windowsCursorPaths) sharedfiletest.Admin {
	return sharedfiletest.Admin{
		Path: paths.Hooks,
		Edit: func(data []byte) []byte {
			document := map[string]any{"version": 1}
			if len(data) != 0 {
				if err := json.Unmarshal(data, &document); err != nil {
					panic(fmt.Sprintf("administrator fixture: hooks.json is not JSON: %v", err))
				}
			}
			events, _ := document["hooks"].(map[string]any)
			if events == nil {
				events = map[string]any{}
				document["hooks"] = events
			}
			events[windowsCursorSharedWriterAdminCommand] = []any{
				map[string]any{"type": "command", "command": windowsCursorSharedWriterAdminCommand},
			}
			edited, err := json.Marshal(document)
			if err != nil {
				panic(err)
			}
			return edited
		},
		Kept: func(data []byte) bool {
			return bytes.Contains(data, []byte(`"`+windowsCursorSharedWriterAdminCommand+`"`))
		},
	}
}

// enrollWindowsCursorOpenAliceForTest enrolls Alice with an open target
// mode on an installed empty guard; the host registration stays closed.
func enrollWindowsCursorOpenAliceForTest(t *testing.T, paths windowsCursorPaths) {
	t.Helper()
	data, err := os.ReadFile(paths.State)
	if err != nil {
		t.Fatal(err)
	}
	var state windowsCursorManagedPolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	alice := WindowsCursorManagedRuntimeTarget{SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\alice\.defenseclaw`}
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
	if hooks, err = connector.SpliceWindowsCursorEnterpriseHooks(hooks, paths.Adapter, "open"); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{paths.Adapter: adapter, paths.State: body, paths.Hooks: hooks} {
		if err := windowsManagedPolicyWriter(path, content, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
		t.Fatalf("fixture guard: active=%t err=%v", active, err)
	}
}

func installWindowsCursorEmptyGuardOverAdminHooksForTest(t *testing.T) windowsCursorPaths {
	t.Helper()
	paths := withWindowsCursorStandaloneSeamsForTest(t)
	writeWindowsCursorAdminHooksForRestoreTest(t, paths)
	installWindowsCursorEmptyGuardForRestoreTest(t, paths)
	return paths
}

func removeWindowsCursorRegistrationForTest(t *testing.T, paths windowsCursorPaths) {
	t.Helper()
	data, err := os.ReadFile(paths.Hooks)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(data, paths.Adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Hooks, cleaned, 0o600); err != nil {
		t.Fatal(err)
	}
}

func windowsCursorSharedWriterOps() []cursorSharedWriterOp {
	setupOpts := connector.SetupOpts{APIAddr: "127.0.0.1:18970", HookExecutable: windowsCursorSharedHooksTestHook}
	setup := func(t *testing.T) (windowsCursorPaths, func() error) {
		paths := withWindowsCursorStandaloneSeamsForTest(t)
		writeWindowsCursorAdminHooksForRestoreTest(t, paths)
		return paths, func() error { return EnsureWindowsStandaloneCursorManagedPolicy(setupOpts) }
	}
	publish := func(t *testing.T) (windowsCursorPaths, func() error) {
		paths := installWindowsCursorEmptyGuardOverAdminHooksForTest(t)
		enrollWindowsCursorOpenAliceForTest(t, paths)
		protectWindowsCursorHooksForAdminsForTest(t, paths.Hooks)
		return paths, func() error {
			return PublishWindowsCursorManagedPolicyTargets([]WindowsCursorManagedRuntimeTarget{})
		}
	}
	repair := func(t *testing.T) (windowsCursorPaths, func() error) {
		paths := installWindowsCursorEmptyGuardOverAdminHooksForTest(t)
		removeWindowsCursorRegistrationForTest(t, paths)
		return paths, func() error {
			_, err := RestoreWindowsCursorManagedAdapter(windowsCursorSharedHooksTestHook)
			return err
		}
	}
	rebuildBoth := func(t *testing.T) (windowsCursorPaths, func() error) {
		paths := installWindowsCursorStandaloneGuardForTest(t, windowsCursorSharedHooksTestHook, true)
		for _, path := range []string{paths.Hooks, paths.Adapter} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		return paths, func() error {
			_, err := RestoreWindowsCursorManagedAdapter(windowsCursorSharedHooksTestHook)
			return err
		}
	}
	teardown := func(t *testing.T) (windowsCursorPaths, func() error) {
		paths := installWindowsCursorEmptyGuardOverAdminHooksForTest(t)
		return paths, DeactivateWindowsCursorManagedPolicy
	}
	refusedUninstall := func(t *testing.T) (windowsCursorPaths, func() error) {
		paths := withWindowsCursorStandaloneSeamsForTest(t)
		opts, snapshot := tearDownWindowsCursorEmptyGuardForRestoreTest(t, paths)
		return paths, func() error { return RestoreWindowsCursorManagedPolicyTeardown(opts, snapshot) }
	}
	failedInstall := func(t *testing.T) (windowsCursorPaths, func() error) {
		paths := withWindowsCursorStandaloneSeamsForTest(t)
		writeWindowsCursorAdminHooksForRestoreTest(t, paths)
		prior := WindowsCursorManagedPolicyTeardownOptions{}
		snapshot, err := CaptureWindowsCursorManagedPolicySnapshot(prior)
		if err != nil || snapshot.PolicyActive {
			t.Fatalf("capture: active=%t err=%v", snapshot.PolicyActive, err)
		}
		installed := installWindowsCursorEmptyGuardForRestoreTest(t, paths)
		return paths, func() error { return RestoreWindowsCursorManagedPolicySnapshot(prior, installed, snapshot) }
	}
	return []cursorSharedWriterOp{
		{name: "setup", prepare: setup, want: "closed"},
		{name: "setup rollback", prepare: setup, fail: true, wantErr: true, want: "inactive"},
		{name: "publication", prepare: publish, want: "closed", steady: true},
		{name: "publication rollback", prepare: publish, fail: true, wantErr: true, want: "closed", steady: true},
		{name: "repair", prepare: repair, want: "closed"},
		{name: "repair rollback", prepare: repair, fail: true, anyErr: true, want: "closed", repair: true},
		{name: "repair hooks.json and adapter lost", prepare: rebuildBoth, want: "closed", absent: true},
		{name: "teardown", prepare: teardown, want: "inactive"},
		{name: "teardown rollback", prepare: teardown, fail: true, wantErr: true, want: "closed"},
		{name: "restore refused uninstall", prepare: refusedUninstall, want: "closed"},
		{name: "restore refused uninstall rollback", prepare: refusedUninstall, fail: true, wantErr: true, want: "inactive"},
		{name: "restore failed install", prepare: failedInstall, want: "inactive"},
		{name: "restore failed install rollback", prepare: failedInstall, fail: true, wantErr: true, want: "closed"},
	}
}

// interleaveWindowsCursorSharedWriterForTest runs change just before
// DefenseClaw's first hooks.json write (before) or just after it lands, and,
// with fail, makes that first publication fail after it lands.
func interleaveWindowsCursorSharedWriterForTest(t *testing.T, hooksPath string, before bool, change, failNext func()) *bool {
	t.Helper()
	changed, failed := false, failNext == nil
	previous := windowsCursorManagedFileSwap
	windowsCursorManagedFileSwap = func(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
		if !strings.EqualFold(request.path, hooksPath) {
			return previous(request)
		}
		if before && !changed {
			changed = true
			change()
		}
		result, err := previous(request)
		if !result.swapped || err != nil {
			return result, err
		}
		if !changed {
			changed = true
			change()
		}
		if !failed {
			failed = true
			failNext()
			return result, errors.New("injected: hooks.json metadata failed after publication")
		}
		return result, err
	}
	t.Cleanup(func() { windowsCursorManagedFileSwap = previous })
	return &changed
}

// watchWindowsCursorMachineGuardForTest checks the files from another
// goroutine while DefenseClaw works on them.
func watchWindowsCursorMachineGuardForTest(paths windowsCursorPaths, steady, present bool) *sharedfiletest.Watch {
	tombstone := windowsCursorManagedTombstone()
	adapterLive := func() (bool, error) {
		data, exists, err := sharedfiletest.ReadShared(paths.Adapter)
		if err != nil {
			return true, err
		}
		return exists && !bytes.Equal(data, tombstone), nil
	}
	return sharedfiletest.StartWatch(func() error {
		before, err := adapterLive()
		if err != nil {
			return nil
		}
		hooks, exists, err := sharedfiletest.ReadShared(paths.Hooks)
		if err != nil {
			if sharedfiletest.Busy(err) {
				return nil
			}
			return err
		}
		if !exists {
			if present || steady {
				return errors.New("hooks.json was missing")
			}
			return nil
		}
		cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(hooks, paths.Adapter)
		if err != nil {
			return nil // a save in progress
		}
		registered := !bytes.Equal(cleaned, hooks)
		if steady && connector.VerifyWindowsCursorEnterpriseHooksRegistered(hooks, paths.Adapter, "closed") != nil &&
			connector.VerifyWindowsCursorEnterpriseHooksRegistered(hooks, paths.Adapter, "open") != nil {
			return fmt.Errorf("the machine guard's registration was missing from hooks.json:\n%s", hooks)
		}
		if registered && !before {
			if after, err := adapterLive(); err == nil && !after {
				return errors.New("hooks.json named the DefenseClaw adapter while it was missing or the allow-only tombstone")
			}
		}
		return nil
	})
}

func requireWindowsCursorSharedWriterOutcomeForTest(t *testing.T, paths windowsCursorPaths, want string) {
	t.Helper()
	hooks, err := os.ReadFile(paths.Hooks)
	if err != nil {
		t.Fatal(err)
	}
	_, active, readErr := ReadWindowsCursorManagedPolicyTargets()
	if want == "inactive" {
		if readErr != nil || active {
			t.Fatalf("want an inactive guard: active=%t err=%v", active, readErr)
		}
		if cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(hooks, paths.Adapter); err != nil || !bytes.Equal(cleaned, hooks) {
			t.Fatalf("hooks.json kept DefenseClaw entries (err %v):\n%s", err, hooks)
		}
		for _, path := range []string{paths.State, paths.Receipt} {
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("an inactive guard left %s (err %v)", path, err)
			}
		}
		return
	}
	if readErr != nil || !active {
		t.Fatalf("want an active guard: active=%t err=%v\n%s", active, readErr, hooks)
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooks(hooks, paths.Adapter, want); err != nil {
		t.Fatalf("hooks.json does not carry the %s registration: %v\n%s", want, err, hooks)
	}
}

func TestWindowsCursorSharedWriterKeepsConcurrentAdministratorChanges(t *testing.T) {
	for _, op := range windowsCursorSharedWriterOps() {
		for _, change := range sharedfiletest.Changes {
			for _, before := range []bool{true, false} {
				timing := map[bool]string{true: "before", false: "after"}[before]
				if op.absent && before && change != sharedfiletest.Content {
					continue // there is no file to change yet
				}
				t.Run(op.name+"/"+string(change)+" "+timing, func(t *testing.T) {
					paths, run := op.prepare(t)
					admin := windowsCursorSharedWriterAdmin(paths)
					var failNext func()
					if op.fail {
						failNext = func() {}
					}
					changed := interleaveWindowsCursorSharedWriterForTest(t, paths.Hooks, before,
						func() { admin.Apply(t, change) }, failNext)
					watch := watchWindowsCursorMachineGuardForTest(paths, op.steady, !op.absent)
					err := run()
					watchErr := watch.Stop()
					if !op.anyErr && op.wantErr != (err != nil) {
						t.Fatalf("operation: err=%v, want an error %t", err, op.wantErr)
					}
					if !*changed {
						t.Fatal("fixture: the administrator's change did not land")
					}
					if watchErr != nil {
						t.Fatalf("watch: %v", watchErr)
					}
					if op.repair {
						windowsCursorManagedFileSwap = swapWindowsCursorManagedFile
						if _, err := RestoreWindowsCursorManagedAdapter(windowsCursorSharedHooksTestHook); err != nil {
							t.Fatalf("quiet repair: %v", err)
						}
					}
					admin.RequireKept(t, change)
					requireWindowsCursorSharedWriterOutcomeForTest(t, paths, op.want)
				})
			}
		}
	}
}
