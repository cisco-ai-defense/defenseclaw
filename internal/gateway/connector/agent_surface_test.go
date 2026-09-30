// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"reflect"
	"testing"
)

// Only an engine version selects a contract: a host version such as the
// Codex extension's 26.5908.31748 would satisfy the open-ended codex
// contract, so a surface that carries only a host version stays unknown.
func TestSurfaceHookContractUsesOnlyTheEngineVersion(t *testing.T) {
	for _, tc := range []struct{ connector, version string }{{"codex", "0.145.0"}, {"claudecode", "2.1.219"}, {"codex", ""}} {
		cli := ResolveSurfaceHookContract(tc.connector, HostSurfaceCLI, tc.version)
		if want := ResolveHookContract(tc.connector, tc.version); !reflect.DeepEqual(cli.HookContractResolution, want) {
			t.Fatalf("%s cli %q = %+v, want ResolveHookContract %+v", tc.connector, tc.version, cli.HookContractResolution, want)
		}
	}
	hostOnly := ResolveSurfaceHookContract("codex", HostSurfaceExtension, "")
	if ok, _ := hostOnly.Admitted(UnverifiedVersionsReport); ok || hostOnly.Status != HookCompatibilityUnknown {
		t.Fatalf("extension without an engine version = %+v, want unknown and not admitted", hostOnly)
	}
	engine := ResolveSurfaceHookContract("claudecode", HostSurfaceExtension, "2.1.219")
	if ok, _ := engine.Admitted(UnverifiedVersionsReport); !ok {
		t.Fatalf("report must admit an unverified surface with a known engine contract: %+v", engine)
	}
	if ok, reason := engine.Admitted(UnverifiedVersionsRefuse); ok || reason == "" {
		t.Fatalf("refuse must not admit an unverified surface")
	}
}
