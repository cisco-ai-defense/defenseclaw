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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A tool running under umask 077 (the MDM wrapper's log setup did) can create
// /Library/Logs/Cisco before the first install. The lifecycle never re-modes
// that shared parent, and launchd cannot open the gateway's log through it,
// so the install is refused before any change instead of failing activation
// after the readiness timeout. Once an administrator opens the parent the
// same install succeeds and the parent keeps the administrator's mode.
func TestDarwinInstallRefusesAnUntraversableSharedParent(t *testing.T) {
	for _, shared := range []string{"/Library/Logs/Cisco", "/opt/cisco"} {
		t.Run(shared, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			parent := h.env.P(shared)
			if err := os.MkdirAll(filepath.Dir(parent), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			payload := h.payload("1.0.0")
			r := h.run(Options{Action: ActionInstall, PayloadDir: payload})
			requireError(t, r, codeApply)
			if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Message, shared+" is 0700") ||
				!strings.Contains(r.Errors[0].Message, "chmod 0755 "+shared) {
				t.Fatalf("errors = %+v, want the untraversable parent %s named with its fix", r.Errors, shared)
			}
			if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || h.services.isActive(labelGateway) {
				t.Fatal("the install changed the host despite an untraversable shared parent")
			}

			if err := os.Chmod(parent, 0o711); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}))
			if got := h.mode(shared); got != 0o711 {
				t.Fatalf("%s mode %04o after install, want the administrator's 0711 kept", shared, got)
			}
		})
	}
}

// On a Mac without /opt/cisco (or /opt) the first directory the lifecycle
// creates is its own 0700 transaction directory. Its missing ancestors must
// still be created 0755, also under the MDM wrapper's umask 077: the
// lifecycle never re-modes a shared parent that already exists, so a closed
// /opt or /opt/cisco would keep agent users from the hook binary and the
// service account from its state for the life of the install.
func TestDarwinFreshInstallCreatesTraversableSharedParents(t *testing.T) {
	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	for _, dir := range []string{"/opt", "/opt/cisco", h.env.Layout.InstallRoot, "/Library/Logs/Cisco", h.env.Layout.LogDir} {
		if got := h.mode(dir); got != 0o755 {
			t.Fatalf("%s mode %04o after a fresh install under umask 077, want 0755", dir, got)
		}
	}
	if got := h.mode(h.env.Layout.LifecycleDir); got != 0o700 {
		t.Fatalf("lifecycle dir mode %04o, want 0700", got)
	}
}
