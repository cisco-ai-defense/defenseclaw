// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// diskState is every path below root with its type, mode and, for a file, a
// digest of its content: a refused uninstall must leave all of it as it was.
func diskState(t *testing.T, root string) map[string]string {
	t.Helper()
	state := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		switch {
		case info.Mode().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += fmt.Sprintf(" %x", sha256.Sum256(data))
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value += " -> " + target
		}
		state[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func diskChanges(before, after map[string]string) []string {
	var changes []string
	for path, value := range before {
		if now, ok := after[path]; !ok {
			changes = append(changes, "removed "+path)
		} else if now != value {
			changes = append(changes, "changed "+path+": "+value+" -> "+now)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			changes = append(changes, "added "+path)
		}
	}
	return changes
}

// GAP-1440: an uninstall that could not remove a machine-state folder failed
// after it had stopped the services and removed the binaries of a payload
// install or a macOS pkg (the CLI with them), so it could not be rerun. A
// state folder the uninstall cannot empty, or one whose parent it cannot
// write, is found before anything changes, on a plain uninstall and on a
// purge: every file and folder, the services, the per-user hooks and the
// service account stay as they were, and the rerun after the cause is
// cleared finishes.
func TestUninstallChangesNothingWhileAStateFolderCannotBeEmptied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove the entries of a read-only folder")
	}
	blockers := []struct {
		name string
		// lock makes a state folder unremovable and returns the folder to
		// unlock and the canonical path the refusal names.
		lock func(h *testHost) (string, string)
	}{
		{"a folder that cannot be emptied", func(h *testHost) (string, string) {
			stuck := filepath.Join(h.env.P(h.env.Layout.DataDir), "stuck")
			if err := os.MkdirAll(stuck, 0o755); err != nil {
				h.t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stuck, "file"), []byte("x"), 0o600); err != nil {
				h.t.Fatal(err)
			}
			return stuck, filepath.Join(h.env.Layout.DataDir, "stuck")
		}},
		{"a read-only parent of a state folder", func(h *testHost) (string, string) {
			return filepath.Dir(h.env.P(h.env.Layout.LogDir)), filepath.Dir(h.env.Layout.LogDir)
		}},
	}
	for _, goos := range []string{"linux", "darwin"} {
		for _, purge := range []bool{false, true} {
			for _, blocker := range blockers {
				t.Run(fmt.Sprintf("%s/purge=%v/%s", goos, purge, blocker.name), func(t *testing.T) {
					h := newTestHost(t, goos)
					requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
					locked, named := blocker.lock(h)
					if err := os.Chmod(locked, 0o555); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
					before := diskState(t, h.env.Root)
					h.services.mu.Lock()
					active, serviceCalls := maps.Clone(h.services.active), len(h.services.calls)
					h.services.mu.Unlock()
					removeAllRan := false
					h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
						removeAllRan = true
						return CommandResult{Stdout: []byte(`{"ok":true}`)}, nil
					}}

					failed := h.run(Options{Action: ActionUninstall, Purge: purge})
					requireError(t, failed, codeUninstall)
					got := messagesOf(failed.Errors, codeUninstall)
					command := h.env.lifecycleCommand(ActionUninstall)
					if purge {
						command += " --purge"
					}
					clear := "`chattr -i`"
					if goos == "darwin" {
						clear = "`chflags nouchg` or `chflags noschg`"
					}
					for _, want := range []string{"nothing was changed", named, clear, "rerun `" + command + "`"} {
						if !strings.Contains(got, want) {
							t.Fatalf("the refusal does not say %q: %s", want, got)
						}
					}
					if changes := diskChanges(before, diskState(t, h.env.Root)); len(changes) > 0 {
						t.Fatalf("the refused uninstall changed the disk:\n%s", strings.Join(changes, "\n"))
					}
					h.services.mu.Lock()
					sameServices := maps.Equal(active, h.services.active)
					newCalls := append([]string(nil), h.services.calls[serviceCalls:]...)
					h.services.mu.Unlock()
					if !sameServices || len(newCalls) > 0 {
						t.Fatalf("the refused uninstall changed the services (calls %v)", newCalls)
					}
					if removeAllRan {
						t.Fatal("the refused uninstall removed the per-user hook registrations")
					}
					if _, ok, _ := h.accounts.Lookup(context.Background(), h.env.Layout.ServiceUser); !ok {
						t.Fatal("the refused uninstall removed the service account")
					}

					if err := os.Chmod(locked, 0o755); err != nil {
						t.Fatal(err)
					}
					retry := h.run(Options{Action: ActionUninstall, Purge: purge})
					requireOK(t, retry)
					gateway := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
					if retry.Noop || !removeAllRan || exists(gateway) || exists(h.env.deploymentPath()) ||
						exists(h.env.P(h.env.Layout.DataDir)) || exists(h.env.P(h.env.Layout.LogDir)) {
						t.Fatalf("the rerun did not finish the removal (noop %v, remove-all ran %v)", retry.Noop, removeAllRan)
					}
				})
			}
		}
	}
}

// The check refuses only state the uninstall removes: what it keeps (all of
// it with --keep-state, the administrator policies of a plain Linux
// uninstall) may be unremovable, and the uninstall finishes. A purge removes
// the policies too, so there they are checked.
func TestUninstallStateCheckLeavesKeptStateAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove the entries of a read-only folder")
	}
	cases := []struct {
		name   string
		opts   Options
		folder func(l managed.StandaloneLayout) string
		refuse bool
	}{
		{"keep-state, a data folder", Options{Action: ActionUninstall, KeepState: true}, func(l managed.StandaloneLayout) string { return l.DataDir }, false},
		{"plain, an administrator policy folder", Options{Action: ActionUninstall}, func(l managed.StandaloneLayout) string { return l.PolicyDir }, false},
		{"purge, an administrator policy folder", Options{Action: ActionUninstall, Purge: true}, func(l managed.StandaloneLayout) string { return l.PolicyDir }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			stuck := filepath.Join(h.env.P(tc.folder(h.env.Layout)), "stuck")
			if err := os.MkdirAll(stuck, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stuck, "file"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(stuck, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(stuck, 0o755) })
			result := h.run(tc.opts)
			if tc.refuse {
				requireError(t, result, codeUninstall)
				if got := messagesOf(result.Errors, codeUninstall); !strings.Contains(got, "nothing was changed") || !exists(h.env.deploymentPath()) {
					t.Fatalf("the purge did not refuse the unremovable policy folder before it changed anything: %s", got)
				}
				return
			}
			requireOK(t, result)
			if !exists(filepath.Join(stuck, "file")) || exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) {
				t.Fatal("the uninstall did not finish while keeping the kept state")
			}
		})
	}
}
