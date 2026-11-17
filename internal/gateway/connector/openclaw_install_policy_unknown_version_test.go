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

package connector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// unknownVersionFixture is an OpenClaw home with no install policy and a
// trusted defenseclaw-gateway, without the OpenClaw extension bundle: setup's
// install policy step is applyOpenClawInstallPolicy, and RefreshInstallPolicy
// is the gateway's refresh.
func unknownVersionFixture(t *testing.T) (configPath, command string, opts SetupOpts) {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "openclaw-home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath = filepath.Join(home, "openclaw.json")
	if err := os.WriteFile(configPath, []byte("{\n  gateway: { port: 18789 },\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	command = filepath.Join(dir, "bin", "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(command), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(command, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	prevExe, prevTrust := openClawInstallPolicyExecutable, openClawInstallPolicyTrusted
	t.Cleanup(func() { openClawInstallPolicyExecutable, openClawInstallPolicyTrusted = prevExe, prevTrust })
	openClawInstallPolicyExecutable = func() (string, error) { return command, nil }
	openClawInstallPolicyTrusted = func(string, string, string) error { return nil }
	opts = SetupOpts{
		DataDir: filepath.Join(dir, "data"), OpenClawHome: home, OpenClawConfigPath: configPath,
		APIAddr: "127.0.0.1:18970", AgentVersion: "2026.11.3", OpenClawInstallPolicy: true, OpenClawInstallPolicyTimeoutMs: 45000,
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return configPath, command, opts
}

func setupOpenClawInstallPolicy(t *testing.T, configPath string, opts SetupOpts) string {
	t.Helper()
	state, err := applyOpenClawInstallPolicy(configPath, opts)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	return state
}

func openClawInstallPolicySavedState(t *testing.T, dataDir string) (state, version string) {
	t.Helper()
	data, err := os.ReadFile(openClawInstallPolicyStatePath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		State           string `json:"state"`
		OpenClawVersion string `json:"openclaw_version"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	return rec.State, rec.OpenClawVersion
}

// GAP-1198 review (P2): setup registered the install policy under OpenClaw
// 2026.11.3; then setup or a refresh runs while the version is unknown (the
// cache reads "" or garbage: openclaw replaced mid-scan, a probe timeout, a
// shell without openclaw on PATH). Before, an unknown version read as "not
// wanted" and removed the registered policy, so installs skipped DefenseClaw
// (fail-open). It stays now, and the state file keeps the version it was
// written under.
func TestOpenClawInstallPolicyUnknownVersionKeepsARegisteredPolicy(t *testing.T) {
	for _, unknown := range []string{"", "garbage"} {
		t.Run("version="+unknown, func(t *testing.T) {
			configPath, command, opts := unknownVersionFixture(t)
			c := NewOpenClawConnector()
			if state := setupOpenClawInstallPolicy(t, configPath, opts); state != openClawInstallPolicyRegistered {
				t.Fatalf("setup under 2026.11.3: %q", state)
			}
			want := openClawInstallPolicyBlock(opts, command)
			unknownOpts := opts
			unknownOpts.AgentVersion = unknown
			state, err := c.RefreshInstallPolicy(unknownOpts)
			if err != nil || state != "not changed: OpenClaw version unknown" {
				t.Errorf("refresh: state %q, err %v", state, err)
			}
			if policy, present := installPolicyIn(t, configPath); !present || !reflect.DeepEqual(policy, want) {
				t.Fatalf("a refresh under an unknown OpenClaw version removed the install policy:\n%s", mustReadFileString(t, configPath))
			}
			if state := setupOpenClawInstallPolicy(t, configPath, unknownOpts); state != "not changed: OpenClaw version unknown" {
				t.Errorf("setup under an unknown version: state %q", state)
			}
			if policy, present := installPolicyIn(t, configPath); !present || !reflect.DeepEqual(policy, want) {
				t.Fatalf("setup under an unknown OpenClaw version removed the install policy:\n%s", mustReadFileString(t, configPath))
			}
			if _, ok := loadOpenClawInstallPolicyRecord(opts.DataDir); !ok {
				t.Fatal("the install policy record was dropped")
			}
			if state, version := openClawInstallPolicySavedState(t, opts.DataDir); state != openClawInstallPolicyRegistered || version != "2026.11.3" {
				t.Fatalf("saved state %q under %q, want registered under 2026.11.3", state, version)
			}
		})
	}
}

// With no record, setup on an OpenClaw of no known version keeps what it did:
// it does not register the block. Turning install_policy off removes a
// registered block whatever the version.
func TestOpenClawInstallPolicyUnknownVersionWithoutARecordOrWhenOff(t *testing.T) {
	configPath, _, opts := unknownVersionFixture(t)
	c := NewOpenClawConnector()
	unknown := opts
	unknown.AgentVersion = ""
	setupOpenClawInstallPolicy(t, configPath, unknown)
	if _, present := installPolicyIn(t, configPath); present {
		t.Fatal("setup on an OpenClaw of no known version registered the install policy")
	}
	if state, _ := openClawInstallPolicySavedState(t, opts.DataDir); !strings.HasPrefix(state, `not registered: OpenClaw "" has no security.installPolicy`) {
		t.Fatalf("state %q", state)
	}
	if state := setupOpenClawInstallPolicy(t, configPath, opts); state != openClawInstallPolicyRegistered {
		t.Fatalf("setup under 2026.11.3: %q", state)
	}
	off := unknown
	off.OpenClawInstallPolicy = false
	if state, err := c.RefreshInstallPolicy(off); err != nil || state != openClawInstallPolicyOff {
		t.Fatalf("refresh off: %q %v", state, err)
	}
	if _, present := installPolicyIn(t, configPath); present {
		t.Fatal("install_policy off under an unknown version left the block")
	}
}

// GAP-1198 review: a downgrade to a version that parses still fails closed:
// 2026.11.3 -> 2026.8.35 below a hardened Windows root (the trust check
// refuses an OpenClaw that counts inherit-only entries) and 2026.11.3 ->
// 2026.8.34 (no security.installPolicy) remove the registered block.
func TestOpenClawInstallPolicyDowngradeStillRemovesTheBlock(t *testing.T) {
	for _, tc := range []struct{ version, state string }{
		{"2026.8.35", "not registered: OpenClaw 2026.8.35 is too old for strict install policy on Windows"},
		{"2026.8.34", `not registered: OpenClaw "2026.8.34" has no security.installPolicy`},
	} {
		t.Run(tc.version, func(t *testing.T) {
			configPath, _, opts := unknownVersionFixture(t)
			openClawInstallPolicyTrusted = func(_, _, version string) error {
				if openClawSkipsInheritOnlyACEs(version) {
					return nil
				}
				return &openClawInstallPolicyTooOldError{version: NormalizeAgentVersion("openclaw", version), cause: errors.New(`C:\ has the inherit-only entry CREATOR OWNER`)}
			}
			c := NewOpenClawConnector()
			setupOpenClawInstallPolicy(t, configPath, opts)
			if _, present := installPolicyIn(t, configPath); !present {
				t.Fatal("setup under 2026.11.3 did not register the install policy")
			}
			down := opts
			down.AgentVersion = tc.version
			state, err := c.RefreshInstallPolicy(down)
			if err != nil || !strings.HasPrefix(state, tc.state) {
				t.Fatalf("refresh: state %q, err %v", state, err)
			}
			if _, present := installPolicyIn(t, configPath); present {
				t.Fatalf("a downgrade to %s left the install policy registered", tc.version)
			}
			if _, version := openClawInstallPolicySavedState(t, opts.DataDir); version != tc.version {
				t.Fatalf("state saved under %q, want %s", version, tc.version)
			}
		})
	}
}
