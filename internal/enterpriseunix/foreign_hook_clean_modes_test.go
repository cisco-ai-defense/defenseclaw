// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-6:GAP-0278: the lifecycle's state lists did not name the gateway's
// clean-session folder (rel-1-0-3:GAP-0352). verify now reports an account
// folder or entry with another mode or owner, repair gives back the modes the
// gateway writes (0711 folders, 0644 entries, the service account's), and a
// file the gateway is still writing is left alone.
func TestVerifyAndRepairTheCleanSessionEntryModes(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			requireOK(t, h.run(Options{Action: ActionVerify}))
			account := h.accounts.accounts[h.env.Layout.ServiceUser]
			service := [2]int{account.UID, account.GID}
			root := managed.ForeignHookCleanDir(h.env.Layout.DataDir)
			if mode := h.mode(root); mode != 0o711 {
				t.Fatalf("install left %s at %04o, want 0711", root, mode)
			}
			uidDir := filepath.Join(root, "1001")
			entry := filepath.Join(uidDir, "p-0123456789abcdef0123456789abcdef01234567.json")
			temp := filepath.Join(uidDir, enterprisepolicy.ForeignHookCleanMirrorTempPrefix+"123")
			if err := os.Mkdir(h.env.P(uidDir), 0o711); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.env.P(uidDir), 0o711); err != nil {
				t.Fatal(err)
			}
			for path, mode := range map[string]os.FileMode{entry: 0o644, temp: 0o600} {
				if err := os.WriteFile(h.env.P(path), []byte("{}\n"), mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(h.env.P(path), mode); err != nil {
					t.Fatal(err)
				}
				h.owners[h.env.P(path)] = service
			}
			h.owners[h.env.P(uidDir)] = service
			if problems := h.env.stateModeProblems(account); len(problems) != 0 {
				t.Fatalf("the modes the gateway writes are reported: %v", problems)
			}

			if err := os.Chmod(h.env.P(uidDir), 0o777); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.env.P(entry), 0o666); err != nil {
				t.Fatal(err)
			}
			problems := h.env.stateModeProblems(account)
			if len(problems) != 1 || !strings.Contains(problems[0], "2 entries under "+root) {
				t.Fatalf("verify does not name the loosened clean-session entries: %v", problems)
			}
			verify := h.run(Options{Action: ActionVerify})
			requireError(t, verify, codeVerify)
			if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, root) {
				t.Fatalf("verify does not name %s: %s", root, got)
			}
			requireOK(t, h.run(Options{Action: ActionRepair}))
			for path, want := range map[string]os.FileMode{uidDir: 0o711, entry: 0o644, temp: 0o600} {
				if mode := h.mode(path); mode != want {
					t.Errorf("repair left %s at %04o, want %04o", path, mode, want)
				}
			}
			requireOK(t, h.run(Options{Action: ActionVerify}))
		})
	}
}

// A chmod -R a+rX over the deployment made the clean-session folder
// listable (0755), which names every account with a clean session: the
// pre-lock pass takes the extra bits away like for the other private folders.
func TestClosePrivateDirsClosesTheCleanSessionFolder(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	root := managed.ForeignHookCleanDir(h.env.Layout.DataDir)
	if err := os.Chmod(h.env.P(root), 0o757); err != nil {
		t.Fatal(err)
	}
	h.env.closePrivateDirs(context.Background())
	if mode := h.mode(root); mode != 0o711 {
		t.Fatalf("closePrivateDirs left %s at %04o, want 0711", root, mode)
	}
}

// A failed first install removes the clean-session folder it created with
// the entries the gateway wrote during activation, so the retry finds no
// leftover.
func TestRollbackRemovesTheCleanSessionFolderItCreated(t *testing.T) {
	h := newTestHost(t, "linux")
	root := managed.ForeignHookCleanDir(h.env.Layout.DataDir)
	entry := filepath.Join(h.env.P(root), "1001", "p-x.json")
	if err := os.MkdirAll(filepath.Dir(entry), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.env.removeCreatedDirs(&snapshot{Entries: []snapshotEntry{{Path: root, Dir: true}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(h.env.P(root)); !os.IsNotExist(err) {
		t.Fatalf("the rollback kept %s: %v", root, err)
	}
}
