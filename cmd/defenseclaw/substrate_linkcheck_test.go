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

package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGatewayStartsWithSubstrateAndOpenShellAPIs builds defenseclaw-gateway,
// which links the vendored Substrate API stubs (substrate-controller) and
// the OpenShell SDK, and runs --version. Before GAP-0014 both registered extension 50000 on the
// descriptor options and the binary panicked at init, before any command.
func TestGatewayStartsWithSubstrateAndOpenShellAPIs(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the gateway")
	}
	bin := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	deps, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range []string{
		"github.com/NVIDIA/OpenShell/sdk/go/proto/optionsv1",
		"github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1",
	} {
		if !strings.Contains(string(deps), pkg+"\n") {
			t.Fatalf("the gateway does not link %s", pkg)
		}
	}
	cmd := exec.Command(bin, "--version")
	cmd.Env = append(cmd.Environ(), "GOLANG_PROTOBUF_REGISTRATION_CONFLICT=panic")
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "panic") || strings.Contains(string(out), "conflict") {
		t.Fatalf("defenseclaw-gateway --version: %v\n%s", err, out)
	}
}
