// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kitStates are the MDM wrapper's state folders by their real path: on
// macOS /var links to /private/var.
var kitStates = map[string]string{"linux": "/var/lib/defenseclaw-mdm", "darwin": "/private/var/db/defenseclaw-mdm"}

// plantKitJournal installs the deployment and leaves an unsettled kit
// rotation entry; it returns the journal folder and a hard link to the
// entry's plaintext earlier credential.
func plantKitJournal(t *testing.T, h *testHost, state string) (string, string) {
	t.Helper()
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	journal := h.env.P(filepath.Join(state, "rotation"))
	if err := os.MkdirAll(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"ai-key.value": "old-secret-value", "ai-key.entry": "confirmed=none\n", ".lock": ""} {
		if err := os.WriteFile(filepath.Join(journal, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyOfValue := filepath.Join(t.TempDir(), "copy")
	if err := os.Link(filepath.Join(journal, "ai-key.value"), copyOfValue); err != nil {
		t.Fatal(err)
	}
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{Stdout: []byte(`{"ok":true,"removed":0}`)}, nil
	}}
	return journal, copyOfValue
}

// GAP-1615: an uninstall --purge run directly (not through the MDM
// wrapper's uninstall.sh) removes the wrapper's credential rotation journal
// with the credentials: the plaintext copy of an earlier credential is
// overwritten first, and the wrapper's empty state folder goes with the
// purge. On macOS the journal is checked at its real path: through the /var
// link the administrator-folder check refused it and the purge left it
// (GAP-1848).
func TestUninstallPurgeRemovesTheKitRotationJournal(t *testing.T) {
	for goos, state := range kitStates {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			_, copyOfValue := plantKitJournal(t, h, state)
			if goos == "darwin" {
				// /var is a link to /private/var on macOS: a path through
				// it is not an administrator's folder.
				link := h.env.P("/var/db") + string(filepath.Separator)
				h.env.Trust = func(path string, _ TrustKind) error {
					if strings.HasPrefix(path, link) {
						return errors.New("a symbolic link is in the path")
					}
					return nil
				}
			}
			done := h.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, done)
			if _, err := os.Lstat(h.env.P(state)); !os.IsNotExist(err) {
				t.Fatalf("the wrapper's state folder stayed: %v (warnings %+v)", err, done.Warnings)
			}
			got, err := os.ReadFile(copyOfValue)
			if err != nil || !bytes.Equal(got, make([]byte, len("old-secret-value"))) {
				t.Fatalf("the earlier credential was not overwritten before removal: %q %v", got, err)
			}
		})
	}
}

// GAP-1801: --keep-state keeps the credentials, so it keeps the journal that
// can put the earlier one back: a reinstall or ensure still settles the
// rotation.
func TestUninstallKeepStateKeepsTheKitRotationJournal(t *testing.T) {
	for goos, state := range kitStates {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			journal, copyOfValue := plantKitJournal(t, h, state)
			requireOK(t, h.run(Options{Action: ActionUninstall, KeepState: true}))
			for _, name := range []string{"ai-key.value", "ai-key.entry"} {
				if _, err := os.Lstat(filepath.Join(journal, name)); err != nil {
					t.Fatalf("--keep-state removed the journal's %s: %v", name, err)
				}
			}
			if got, err := os.ReadFile(copyOfValue); err != nil || string(got) != "old-secret-value" {
				t.Fatalf("--keep-state overwrote the earlier credential: %q %v", got, err)
			}
		})
	}
}
