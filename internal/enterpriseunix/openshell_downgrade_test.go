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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// rel-1-0-10:GAP-1781: OpenShell has no down migration. A setup pin below
// the release an account's gateway already ran (and migrated its database
// with) is refused by ensure, naming the accounts and the way back; only
// enterprise.openshell.allow_downgrade applies it, with a warning for each
// such account. An account whose database is gone, or a host where no
// account ran a newer release, is not refused.
func TestGAP1781SetupPinBelowWhatAnAccountRan(t *testing.T) {
	setup := func(version string, allow bool) map[string]any {
		s := map[string]any{"install": "setup", "driver": "docker", "version": version}
		if allow {
			s["allow_downgrade"] = true
		}
		return s
	}
	h := newOSHost(t, "linux")
	// No account ran anything yet: the lower pin applies.
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setup(openshell.SupportedMin, false))))
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setup(openshell.InstallerVersion, false))))
	// alice's daemon installed the newer pin and its gateway migrated her
	// database.
	h.installTarballFiles(t, h.alice, openshell.InstallerVersion)
	db := filepath.Join(h.env.P(h.alice.Home), ".local", "state", "openshell", "gateway", "openshell.db")
	if err := os.MkdirAll(filepath.Dir(db), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, []byte("SQLite format 3\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := h.read(h.env.renderedTOMLPath())

	r := h.ensure(sandboxConfig(t, "linux", true, setup(openshell.SupportedMin, false)))
	all := fmt.Sprint(r.Errors, r.Warnings)
	if r.OK || !strings.Contains(all, fmt.Sprintf(`enterprise.openshell.version %q is below the OpenShell these accounts already ran: %s (OpenShell %s)`,
		openshell.SupportedMin, h.alice.Name, openshell.InstallerVersion)) ||
		!strings.Contains(all, "cannot open a database a newer OpenShell migrated") ||
		!strings.Contains(all, "to "+openshell.InstallerVersion+" or newer") ||
		!strings.Contains(all, "enterprise.openshell.allow_downgrade: true") ||
		!strings.Contains(all, "openshell.db (with openshell.db-wal and openshell.db-shm) aside, which loses that account's sandbox records") {
		t.Fatalf("the lower pin is not refused with the accounts and the way back: %+v", r)
	}
	if h.read(h.env.renderedTOMLPath()) != before || h.env.loadOpenShellState().Applied.Version != openshell.InstallerVersion {
		t.Fatal("a refused downgrade applied something")
	}

	// allow_downgrade applies it, and ensure warns for alice (the switch
	// then removes her install record; her own doctor names the cause).
	r = h.ensure(sandboxConfig(t, "linux", true, setup(openshell.SupportedMin, true)))
	requireOK(t, r)
	if v := h.env.loadOpenShellState().Applied.Version; v != openshell.SupportedMin {
		t.Fatalf("applied version = %q", v)
	}
	if res := messagesOf(r.Warnings, "openshell_downgrade"); !strings.Contains(res, h.alice.Name+" already ran OpenShell "+openshell.InstallerVersion+
		", above enterprise.openshell.version "+openshell.SupportedMin) || !strings.Contains(res, "moves ~/.local/state/openshell/gateway/openshell.db") {
		t.Errorf("downgrade warning = %q", res)
	}

	// Once alice moved her database aside, nothing is refused or warned.
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setup(openshell.InstallerVersion, false))))
	h.installTarballFiles(t, h.alice, openshell.InstallerVersion)
	if err := os.Rename(db, db+".aside"); err != nil {
		t.Fatal(err)
	}
	r = h.ensure(sandboxConfig(t, "linux", true, setup(openshell.SupportedMin, false)))
	requireOK(t, r)
	if w := messagesOf(r.Warnings, "openshell_downgrade"); w != "" {
		t.Errorf("warned without a migrated database: %q", w)
	}
}
