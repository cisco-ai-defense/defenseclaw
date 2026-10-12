// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestRenderedEnvironmentCarriesTheTelemetrySwitch(t *testing.T) {
	old := renderedOwnerOK
	renderedOwnerOK = func(fs.FileInfo) bool { return true }
	defer func() { renderedOwnerOK = old }()

	off := writeRendered(t, RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: DriverDocker})
	env, err := RenderedEnvironment(off.Env)
	if err != nil || len(env) != 1 || env[0] != "OPENSHELL_TELEMETRY_ENABLED=false" {
		t.Fatalf("telemetry off: env = %v %v", env, err)
	}
	on := writeRendered(t, RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: DriverDocker, TelemetryEnabled: true})
	if env, err := RenderedEnvironment(on.Env); err != nil || env != nil {
		t.Fatalf("telemetry allowed: env = %v %v, want none", env, err)
	}
	// Only the setting the lifecycle renders is passed on.
	extra := filepath.Join(t.TempDir(), "gateway.env")
	if err := os.WriteFile(extra, []byte("OPENSHELL_TELEMETRY_ENABLED='FALSE'\nLD_PRELOAD=/tmp/x.so\nOPENSHELL_COMPUTE_DRIVER=vm\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if env, err := RenderedEnvironment(extra); err != nil || len(env) != 1 || env[0] != "OPENSHELL_TELEMETRY_ENABLED=false" {
		t.Fatalf("env = %v %v, want only the telemetry switch", env, err)
	}
	if err := os.WriteFile(extra, []byte("OPENSHELL_TELEMETRY_ENABLED=maybe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderedEnvironment(extra); err == nil {
		t.Error("a telemetry switch that is not a boolean is passed on")
	}
	// Not the administrator's file: refused.
	renderedOwnerOK = func(fs.FileInfo) bool { return false }
	if _, err := RenderedEnvironment(off.Env); err == nil {
		t.Error("an environment file root does not own is trusted")
	}
}
