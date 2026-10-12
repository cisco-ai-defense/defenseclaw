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
	"path/filepath"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A second OpenShell gateway of the account (a private one started by hand,
// NVIDIA's own service) shares the MicroVM state of the managed one and
// stopped a running managed sandbox (GAP-0610): the daemon lists the account's
// gateways that are not the managed unit's, and never the managed one.
func TestAccountOpenShellListsTheGatewaysItsUnitDidNotStart(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	cfg := filepath.Join(t.TempDir(), openshell.GatewayTOMLFile)
	s := sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{Install: "prerequisite", Driver: "vm", GatewayPort: 17670,
		GatewayConfigPath: cfg}}
	procs := ""
	r.o.accountProcs = func(context.Context) (string, error) { return procs, nil }

	procs = " 410 /usr/bin/openshell-gateway --config " + cfg + "\n" +
		" 411 /usr/libexec/openshell/openshell-driver-vm --serve\n" +
		" 412 /usr/bin/openshell --help\n"
	if got := r.o.OtherGateways(context.Background(), s); len(got) != 0 {
		t.Fatalf("the managed gateway was listed: %v", got)
	}

	procs += " 520 /home/bob/.local/bin/openshell-gateway --config /home/bob/private.toml\n" +
		" 521 /usr/bin/openshell-gateway --config " + cfg + " --bind-address 127.0.0.1:17999\n"
	want := []string{
		"pid 520: /home/bob/.local/bin/openshell-gateway --config /home/bob/private.toml",
		"pid 521: /usr/bin/openshell-gateway --config " + cfg + " --bind-address 127.0.0.1:17999",
	}
	if got := r.o.OtherGateways(context.Background(), s); !reflect.DeepEqual(got, want) {
		t.Fatalf("other gateways = %v, want %v", got, want)
	}

	// Without the managed command line there is nothing to tell the managed
	// gateway from: nothing is listed.
	s.Enterprise.GatewayConfigPath = ""
	if got := r.o.OtherGateways(context.Background(), s); len(got) != 0 {
		t.Fatalf("judged without the managed command line: %v", got)
	}
}
