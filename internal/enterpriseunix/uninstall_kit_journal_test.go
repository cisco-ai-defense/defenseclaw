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
	"os"
	"path/filepath"
	"testing"
)

// GAP-1615: an uninstall --purge run directly (not through the MDM
// wrapper's uninstall.sh) removes the wrapper's credential rotation journal
// with the credentials: the plaintext copy of an earlier credential is
// overwritten first, and the wrapper's empty state folder goes with the
// purge.
func TestUninstallPurgeRemovesTheKitRotationJournal(t *testing.T) {
	for goos, state := range map[string]string{"linux": "/var/lib/defenseclaw-mdm", "darwin": "/var/db/defenseclaw-mdm"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			journal := h.env.P(filepath.Join(state, "rotation"))
			if err := os.MkdirAll(journal, 0o700); err != nil {
				t.Fatal(err)
			}
			value := filepath.Join(journal, "ai-key.value")
			for name, body := range map[string]string{"ai-key.value": "old-secret-value", "ai-key.entry": "confirmed=none\n", ".lock": ""} {
				if err := os.WriteFile(filepath.Join(journal, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			copyOfValue := filepath.Join(t.TempDir(), "copy")
			if err := os.Link(value, copyOfValue); err != nil {
				t.Fatal(err)
			}
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, done)
			if _, err := os.Lstat(h.env.P(state)); !os.IsNotExist(err) {
				t.Fatalf("the wrapper's state folder stayed: %v", err)
			}
			got, err := os.ReadFile(copyOfValue)
			if err != nil || !bytes.Equal(got, make([]byte, len("old-secret-value"))) {
				t.Fatalf("the earlier credential was not overwritten before removal: %q %v", got, err)
			}
		})
	}
}
