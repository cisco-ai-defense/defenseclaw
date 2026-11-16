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

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// #1296 on a managed computer: the managed gateway reads the
// administrator's openshell.trusted_ca_bundle (administrator-owned) and
// relays the PEM, or why it cannot, in the daemon settings; the daemon's
// configuration carries exactly that, never a CA file of the account's.
func TestManagedSettingsRelayTheTrustedCAs(t *testing.T) {
	saved := openshell.TrustedCAFileCheck
	t.Cleanup(func() { openshell.TrustedCAFileCheck = saved })
	trusted := true
	openshell.TrustedCAFileCheck = func(string, string) error {
		if !trusted {
			return errors.New("writable by group staff")
		}
		return nil
	}
	ca := openshelltest.NewCA(t, "Corp Root CA")
	file := filepath.Join(t.TempDir(), "corp-root.pem")
	if err := os.WriteFile(file, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
	if op := sandboxOperational(cfg, config.OpenShellAdminConfig{}); op.TrustedCAs != "" || op.TrustedCAError != "" {
		t.Fatalf("unset: %+v", op)
	}
	cfg.OpenShell.TrustedCABundle = file
	op := sandboxOperational(cfg, config.OpenShellAdminConfig{})
	if op.TrustedCAs != string(ca.PEM) || op.TrustedCAError != "" {
		t.Fatalf("relayed: %+v", op)
	}
	digest := sandboxSettingsDigest(cfg, config.OpenShellAdminConfig{})
	trusted = false
	op = sandboxOperational(cfg, config.OpenShellAdminConfig{})
	if op.TrustedCAs != "" || !strings.Contains(op.TrustedCAError, "writable by group staff") {
		t.Fatalf("untrusted file: %+v", op)
	}
	if sandboxSettingsDigest(cfg, config.OpenShellAdminConfig{}) == digest {
		t.Fatal("a refused CA file left the settings digest unchanged")
	}

	d := &SandboxDaemon{}
	d.settings = sandboxrelay.DaemonSettings{Enabled: true, Available: true,
		Operational: sandboxrelay.OperationalSettings{TrustedCAs: string(ca.PEM)}}
	got := d.buildConfigWith(nil).OpenShell
	if got.TrustedCAPEM != string(ca.PEM) || got.TrustedCAError != "" || got.TrustedCABundle != "" {
		t.Fatalf("daemon config: %+v", got)
	}
	d.settings.Operational = sandboxrelay.OperationalSettings{TrustedCAError: "refused"}
	if got = d.buildConfigWith(nil).OpenShell; got.TrustedCAPEM != "" || got.TrustedCAError != "refused" {
		t.Fatalf("daemon config, refused: %+v", got)
	}
}
