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

package manager

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestOpenCodeSandboxCreateKeepsLocalServicesDirectOnEveryDriver(t *testing.T) {
	for _, driver := range []openshell.ComputeDriver{openshell.DriverDocker, openshell.DriverVM} {
		t.Run(string(driver), func(t *testing.T) {
			e := newDaemonEnv(t, daemonOptions{driver: driver}, nil)
			useOpenCode(t, e)
			sb := e.create(sandboxapi.CreateRequest{Name: "local-service", Harness: "opencode", Copy: true})
			got, err := e.client.GetSandbox(t.Context(), sb.Name)
			must(t, err)
			env := got.Spec.Environment
			list := env["NO_PROXY"]
			if env["HTTPS_PROXY"] == "" || list != env["no_proxy"] || list != env[openshell.EnvEgressBypass] {
				t.Fatalf("sandbox proxy environment is incomplete")
			}
			seen := map[string]bool{}
			for _, host := range strings.Split(list, ",") {
				seen[host] = true
			}
			for _, host := range []string{"127.0.0.0/8", "127.0.0.1", "::1", "localhost", connector.SandboxIngressHost} {
				if !seen[host] {
					t.Errorf("sandbox proxy exclusions lack %q", host)
				}
			}
			if seen["outside.example"] {
				t.Error("ordinary external destination excluded from the proxy")
			}
		})
	}
}
