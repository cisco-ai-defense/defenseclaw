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

//go:build linux || darwin

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A ~/.config the account cannot write stopped the registration with the
// openshell CLI's opaque "failed to store mTLS bundle" (GAP-0588): the
// refusal names the folder, and the CLI is not run against it.
func TestAccountOpenShellNamesTheFolderItCannotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write any folder")
	}
	fastGatewayWaits(t)
	r := newOpenShellRig(t, "linux")
	r.holder = func(int) int { return 5001 }
	cfgDir, _ := r.o.configDir()
	parent := filepath.Dir(cfgDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	_, err := r.o.Prepare(context.Background(), setupSettings())
	if err == nil || !strings.Contains(err.Error(), "cannot write "+parent) || !strings.Contains(err.Error(), "ask IT") {
		t.Fatalf("an unwritable %s: %v", parent, err)
	}
	if strings.Contains(strings.Join(r.ran(), "\n"), "gateway add") {
		t.Fatalf("the CLI ran against an unwritable folder: %v", r.ran())
	}

	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := r.o.Prepare(context.Background(), setupSettings()); err != nil {
		t.Fatalf("a writable folder: %v", err)
	}
	if !strings.Contains(strings.Join(r.ran(), "\n"), "gateway add") {
		t.Fatalf("the gateway was not registered: %v", r.ran())
	}
}

// The managed unit's gateway never reads the account's own
// ~/.config/openshell/gateway.toml (it runs the administrator's rendered file),
// so an edit there, or an OPENSHELL_GATEWAY_CONFIG pointing at one, changes
// nothing about the gateway that runs and is no settings drift: the file is
// not even read while the managed unit's gateway runs (GAP-0581, GAP-0512).
func TestAccountOpenShellIgnoresAnEditedUserGatewayFileWhileTheManagedUnitRuns(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	r.holder = func(int) int { return 5001 }
	r.active, r.pid = true, 77
	r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	cfg := filepath.Join(t.TempDir(), openshell.GatewayTOMLFile)
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) {
		return openshell.RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: openshell.DriverVM}, "", nil
	}
	read := false
	r.o.readUser = func(string) (*openshell.GatewayConfigState, error) {
		read = true
		return &openshell.GatewayConfigState{ComputeDriver: openshell.DriverDocker}, nil
	}
	userFile := filepath.Join(r.o.home, ".config", "openshell", "gateway.toml")
	if err := os.MkdirAll(filepath.Dir(userFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userFile, []byte("[openshell.gateway]\ncompute_driver = \"docker\"\nbind_address = \"127.0.0.1:17671\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{Install: "prerequisite", Driver: "vm", GatewayPort: 17670,
		GatewayConfigPath: cfg}}
	r.args = "/usr/bin/openshell-gateway --config " + cfg
	if drift, err := r.o.Drift(s); err != nil || len(drift) != 0 || read {
		t.Fatalf("an edited user file is drift: %v %v (read it: %v)", drift, err, read)
	}
}
