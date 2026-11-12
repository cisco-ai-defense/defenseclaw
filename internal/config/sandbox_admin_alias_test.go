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

package config

import (
	"reflect"
	"testing"
)

// The 1.0.9 name is an alias, not a copy: OpenShell callers and the
// runtime-neutral callers share one type, so a floor never converts.
func TestOpenShellAdminConfigIsSandboxAdminConfig(t *testing.T) {
	if reflect.TypeOf(OpenShellAdminConfig{}) != reflect.TypeOf(SandboxAdminConfig{}) {
		t.Fatal("OpenShellAdminConfig is not an alias of SandboxAdminConfig")
	}
	var legacy OpenShellAdminConfig = SandboxAdminConfig{MinProfile: "balanced"}
	if legacy.MinProfile != "balanced" {
		t.Fatalf("alias lost a field: %+v", legacy)
	}
}

// TightenOpenShellAdmin is TightenSandboxAdmin: same result and same
// contradiction for the same inputs.
func TestTightenOpenShellAdminWrapsTightenSandboxAdmin(t *testing.T) {
	base := SandboxAdminConfig{
		MinProfile:       "balanced",
		AllowedHarnesses: []string{"claude-code", "codex"},
		EgressBlock:      []string{"a.example"},
		AllowYolo:        bp(true),
	}
	overlay := &SandboxAdminConfig{
		MinProfile:       "strict",
		AllowedHarnesses: []string{"codex"},
		EgressBlock:      []string{"b.example"},
		AllowYolo:        bp(false),
	}
	want, wantErr := TightenSandboxAdmin(base, overlay)
	got, gotErr := TightenOpenShellAdmin(base, overlay)
	if (wantErr == nil) != (gotErr == nil) || !reflect.DeepEqual(want, got) {
		t.Fatalf("wrapper differs: %+v %v, want %+v %v", got, gotErr, want, wantErr)
	}
	if got.MinProfile != "strict" || !reflect.DeepEqual(got.AllowedHarnesses, []string{"codex"}) {
		t.Fatalf("tighten did not tighten: %+v", got)
	}

	contradiction := &SandboxAdminConfig{Allowed: bp(false), RequiredFor: []string{"codex"}}
	_, wantErr = TightenSandboxAdmin(SandboxAdminConfig{}, contradiction)
	_, gotErr = TightenOpenShellAdmin(SandboxAdminConfig{}, contradiction)
	if wantErr == nil || gotErr == nil || wantErr.Error() != gotErr.Error() {
		t.Fatalf("contradiction differs: %v, want %v", gotErr, wantErr)
	}
}
