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

package openshelltest_test

import (
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// WithDriver reports the driver as a live 0.1.1 gateway does.
func TestWithDriver(t *testing.T) {
	for _, tc := range []struct {
		driver openshell.ComputeDriver
		want   types.ComputeDriverInfo
	}{
		{openshell.DriverDocker, types.ComputeDriverInfo{Name: "docker", DriverName: "docker", DriverVersion: openshell.SupportedMin}},
		{openshell.DriverVM, types.ComputeDriverInfo{Name: "vm", DriverName: "openshell-driver-vm", DriverVersion: openshell.SupportedMin}},
	} {
		info, err := openshelltest.New(openshelltest.WithDriver(tc.driver)).Client(openshell.ClientOptions{}).GatewayInfo(t.Context())
		if err != nil || len(info.ComputeDrivers) != 1 || info.ComputeDrivers[0] != tc.want {
			t.Fatalf("%s: gateway info = %+v, %v", tc.driver, info, err)
		}
		if d, err := openshell.GatewayDriver(info); err != nil || d.Name != tc.driver {
			t.Fatalf("%s: GatewayDriver = %+v, %v", tc.driver, d, err)
		}
	}
}

// The vm fake refuses what the vm driver refuses, so a docker mount request
// never passes for a MicroVM one in a test.
func TestVMDriverRefusesDockerDriverConfig(t *testing.T) {
	f := openshelltest.New(openshelltest.WithDriver(openshell.DriverVM))
	c := f.Client(openshell.ClientOptions{})
	spec := func(cfg map[string]any) *openshell.SandboxSpec {
		return &openshell.SandboxSpec{Template: &openshell.SandboxTemplate{Image: "defenseclaw.invalid/sandbox:x", DriverConfig: cfg}}
	}
	for name, cfg := range map[string]map[string]any{
		"docker-mounts": {"docker": map[string]any{"mounts": []any{map[string]any{"type": "bind", "source": "/", "target": "/host"}}}},
		"vm-unknown":    {"vm": map[string]any{"mounts": []any{}}},
	} {
		if _, err := c.CreateSandbox(t.Context(), name, spec(cfg), openshell.CreateSandboxOptions{}); !openshell.IsInvalidArgument(err) || !strings.Contains(err.Error(), "driver_config") {
			t.Fatalf("%s: create = %v", name, err)
		}
	}
	for name, cfg := range map[string]map[string]any{
		"none": nil, "gpus": {"vm": map[string]any{"gpu_device_ids": []any{"0"}}},
	} {
		if _, err := c.CreateSandbox(t.Context(), name, spec(cfg), openshell.CreateSandboxOptions{}); err != nil {
			t.Fatalf("%s: create = %v", name, err)
		}
	}
	// The docker fake takes its bind mounts as before.
	d := openshelltest.New().Client(openshell.ClientOptions{})
	if _, err := d.CreateSandbox(t.Context(), "docker-mounts", spec(map[string]any{"docker": map[string]any{"mounts": []any{}}}), openshell.CreateSandboxOptions{}); err != nil {
		t.Fatalf("docker create = %v", err)
	}
}
