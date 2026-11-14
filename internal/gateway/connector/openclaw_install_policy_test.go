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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// installPolicyFixture is the JSON5 fixture with install admission on for
// OpenClaw 2026.11.3 and a fake defenseclaw-gateway as the command.
func installPolicyFixture(t *testing.T, pristine string) (configPath, command string, opts SetupOpts) {
	t.Helper()
	_, configPath, opts = openClawJSON5Fixture(t, t.TempDir())
	if pristine != "" {
		if err := os.WriteFile(configPath, []byte(pristine), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	command = filepath.Join(t.TempDir(), "bin", "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(command), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(command, []byte("fake"), 0o755); err != nil {
		t.Fatal(err)
	}
	prevExe, prevTrust := openClawInstallPolicyExecutable, openClawInstallPolicyTrusted
	openClawInstallPolicyExecutable = func() (string, error) { return command, nil }
	openClawInstallPolicyTrusted = func(string, string) error { return nil }
	var notice bytes.Buffer
	prevOut := openClawTeardownNoticeOutput
	openClawTeardownNoticeOutput = &notice
	t.Cleanup(func() {
		openClawInstallPolicyExecutable, openClawInstallPolicyTrusted = prevExe, prevTrust
		openClawTeardownNoticeOutput = prevOut
	})
	opts.AgentVersion = "2026.11.3"
	opts.OpenClawInstallPolicy = true
	opts.OpenClawInstallPolicyTimeoutMs = 45000
	return configPath, command, opts
}

func installPolicyIn(t *testing.T, configPath string) (interface{}, bool) {
	t.Helper()
	policy, present, _ := openClawInstallPolicyOf(readOpenClawJSON5(t, configPath))
	return policy, present
}

// Setup writes the block on OpenClaw 2026.11.3, teardown of an unchanged
// file restores its bytes, and teardown of a file OpenClaw saved since
// takes out only the block (and the security object setup created).
func TestOpenClawInstallPolicyWrittenAndRemovedExactly(t *testing.T) {
	for _, edited := range []bool{false, true} {
		configPath, command, opts := installPolicyFixture(t, openClawCombinedSpelling)
		c := NewOpenClawConnector()
		if err := c.registerPlugin(opts); err != nil {
			t.Fatalf("setup: %v", err)
		}
		policy, present := installPolicyIn(t, configPath)
		if !present {
			t.Fatalf("setup did not write security.installPolicy:\n%s", mustReadFileString(t, configPath))
		}
		want := openClawInstallPolicyBlock(opts, command)
		if !reflect.DeepEqual(policy, want) {
			t.Fatalf("installPolicy = %#v\nwant %#v", policy, want)
		}
		exec := want["exec"].(map[string]interface{})
		if exec["command"] != command || exec["timeoutMs"] != float64(45000) || exec["noOutputTimeoutMs"] != float64(45000) ||
			!reflect.DeepEqual(exec["args"], []interface{}{"connector", "openclaw", "install-policy"}) ||
			!reflect.DeepEqual(exec["trustedDirs"], []interface{}{filepath.Dir(command)}) ||
			exec["env"].(map[string]interface{})["DEFENSECLAW_HOME"] != opts.DataDir {
			t.Fatalf("exec block = %#v", exec)
		}
		// A second setup (every gateway start) changes nothing.
		before := mustReadFileString(t, configPath)
		if err := c.registerPlugin(opts); err != nil {
			t.Fatalf("second setup: %v", err)
		}
		if got := mustReadFileString(t, configPath); got != before {
			t.Fatalf("a repeated setup rewrote openclaw.json")
		}
		if edited {
			saved := strings.Replace(before, "\"gateway\"", "\"meta\": {\"lastTouchedVersion\": \"x\"},\n  \"gateway\"", 1)
			if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("teardown: %v", err)
		}
		got := mustReadFileString(t, configPath)
		if !edited && got != openClawCombinedSpelling {
			t.Fatalf("an unedited file did not restore exactly:\n%s", got)
		}
		cfg := readOpenClawJSON5(t, configPath)
		if _, has := cfg["security"]; has {
			t.Fatalf("edited=%v: teardown left a security object:\n%s", edited, got)
		}
		if edited && !strings.Contains(got, "lastTouchedVersion") {
			t.Fatalf("teardown lost the OpenClaw save:\n%s", got)
		}
		if _, err := os.Stat(openClawInstallPolicyRecordPath(opts.DataDir)); !os.IsNotExist(err) {
			t.Fatalf("edited=%v: the install policy record outlived teardown: %v", edited, err)
		}
	}
}

// An operator installPolicy stays as it is through setup and teardown, and
// setup says once that it left it.
func TestOpenClawInstallPolicyLeavesTheOperatorPolicy(t *testing.T) {
	const own = `{"security": {"installPolicy": {"enabled": true, "exec": {"source": "exec", "command": "/usr/local/bin/my-policy"}}, "audit": true}}`
	configPath, _, opts := installPolicyFixture(t, own)
	var notice bytes.Buffer
	openClawTeardownNoticeOutput = &notice
	c := NewOpenClawConnector()
	for i := 0; i < 2; i++ {
		if err := c.registerPlugin(opts); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	policy, _ := installPolicyIn(t, configPath)
	exec := policy.(map[string]interface{})["exec"].(map[string]interface{})
	if exec["command"] != "/usr/local/bin/my-policy" || len(exec) != 2 {
		t.Fatalf("setup changed the operator policy: %#v", policy)
	}
	if strings.Count(notice.String(), "already has a security.installPolicy") != 1 {
		t.Fatalf("setup should say once that it left the operator policy: %q", notice.String())
	}
	if _, err := os.Stat(openClawInstallPolicyRecordPath(opts.DataDir)); !os.IsNotExist(err) {
		t.Fatalf("setup recorded a policy it did not write")
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	policy, present := installPolicyIn(t, configPath)
	if !present || policy.(map[string]interface{})["exec"].(map[string]interface{})["command"] != "/usr/local/bin/my-policy" {
		t.Fatalf("teardown removed the operator policy:\n%s", mustReadFileString(t, configPath))
	}
}

// Nothing is written below OpenClaw 2026.8.35, for an unknown version, or
// with install_policy off; turning it off removes the block setup wrote.
func TestOpenClawInstallPolicyNotWrittenWhenOffOrOld(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		on      bool
	}{
		{"older OpenClaw", "2026.8.34", true},
		{"2026.6.8", "2026.6.8", true},
		{"unknown version", "", true},
		{"off", "2026.11.3", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath, _, opts := installPolicyFixture(t, "")
			opts.AgentVersion = tc.version
			opts.OpenClawInstallPolicy = tc.on
			if err := NewOpenClawConnector().registerPlugin(opts); err != nil {
				t.Fatalf("setup: %v", err)
			}
			if _, present := installPolicyIn(t, configPath); present {
				t.Fatalf("setup wrote security.installPolicy:\n%s", mustReadFileString(t, configPath))
			}
		})
	}
	configPath, _, opts := installPolicyFixture(t, `{"security": {"audit": true}}`)
	opts.AgentVersion = OpenClawInstallPolicySince
	c := NewOpenClawConnector()
	if err := c.registerPlugin(opts); err != nil {
		t.Fatal(err)
	}
	if _, present := installPolicyIn(t, configPath); !present {
		t.Fatalf("not written on %s", OpenClawInstallPolicySince)
	}
	opts.OpenClawInstallPolicy = false
	if err := c.registerPlugin(opts); err != nil {
		t.Fatal(err)
	}
	cfg := readOpenClawJSON5(t, configPath)
	if security, _ := cfg["security"].(map[string]interface{}); security == nil || security["audit"] != true || security["installPolicy"] != nil {
		t.Fatalf("turning it off must remove only the block and keep the security object it found:\n%s", mustReadFileString(t, configPath))
	}
}

// A block the operator changed after setup is theirs: teardown leaves it.
func TestOpenClawInstallPolicyTeardownLeavesAChangedBlock(t *testing.T) {
	configPath, _, opts := installPolicyFixture(t, "")
	c := NewOpenClawConnector()
	if err := c.registerPlugin(opts); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(mustReadFileString(t, configPath), "\"timeoutMs\": 45000", "\"timeoutMs\": 99000", 1)
	if err := os.WriteFile(configPath, []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if !strings.Contains(mustReadFileString(t, configPath), "99000") {
		t.Fatalf("teardown removed a block the operator changed:\n%s", mustReadFileString(t, configPath))
	}
}

// The separate-user layout: the block the administrator merges carries
// the token file, the gateway address and the outage answer, and setup
// asks for it only while it is missing or stale.
func TestOpenClawInstallPolicySeparateUserBlock(t *testing.T) {
	_, command, opts := installPolicyFixture(t, "")
	opts.OpenClawPluginAccount = "oc"
	opts.OpenClawPluginTokenFile = "/etc/defenseclaw/openclaw/plugin.token"
	opts.OpenClawInstallPolicyFailsClosed = true
	paths := openClawPaths{external: "/opt/defenseclaw/openclaw/defenseclaw"}
	if !strings.Contains(openClawSeparateUserBlock(opts, paths), "installPolicy") {
		t.Fatalf("the separate-user block lacks the install policy")
	}
	want := openClawInstallPolicyBlock(opts, command)
	env := want["exec"].(map[string]interface{})["env"].(map[string]interface{})
	if env[OpenClawInstallPolicyTokenFileEnv] != opts.OpenClawPluginTokenFile || env[OpenClawInstallPolicyAPIEnv] != "127.0.0.1:18970" ||
		env[OpenClawInstallPolicyOutageEnv] != "closed" || env["DEFENSECLAW_HOME"] != nil {
		t.Fatalf("separate-user env = %#v", env)
	}
	missing := func(cfg map[string]interface{}) []string { return openClawSeparateUserInstallPolicyMissing(cfg, opts) }
	if got := missing(map[string]interface{}{}); len(got) != 1 {
		t.Fatalf("an absent block is not reported: %v", got)
	}
	if got := missing(map[string]interface{}{"security": map[string]interface{}{"installPolicy": want}}); len(got) != 0 {
		t.Fatalf("an exact block is reported: %v", got)
	}
	stale := openClawInstallPolicyBlock(SetupOpts{OpenClawPluginAccount: "oc", OpenClawInstallPolicyTimeoutMs: 1000}, command)
	if got := missing(map[string]interface{}{"security": map[string]interface{}{"installPolicy": stale}}); len(got) != 1 {
		t.Fatalf("a stale DefenseClaw block is not reported: %v", got)
	}
	own := map[string]interface{}{"exec": map[string]interface{}{"command": "/usr/local/bin/my-policy"}}
	if got := missing(map[string]interface{}{"security": map[string]interface{}{"installPolicy": own}}); len(got) != 0 {
		t.Fatalf("the operator policy is reported as missing: %v", got)
	}
	opts.OpenClawInstallPolicy = false
	if strings.Contains(openClawSeparateUserBlock(opts, paths), "installPolicy") || len(missing(map[string]interface{}{})) != 0 {
		t.Fatalf("install admission off still asks for the block")
	}
}
