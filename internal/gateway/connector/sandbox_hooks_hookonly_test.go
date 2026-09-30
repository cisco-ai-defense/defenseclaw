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

package connector

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The sandbox variants of the hook-only connectors that run in OpenShell
// images (Hermes, OpenHands, Antigravity). Their hooks run in the shared
// tables of sandbox_hooks_shell_test.go against each harness's own block
// signal.

// TestHookOnlySandboxArtifacts: the root-owned Hermes managed .env pins the
// switches Hermes would otherwise take from the workload-writable
// ~/.hermes/.env, and the OpenHands and agy hooks seeded in HOME are byte for
// byte the root-owned copies their launchers restore them from.
func TestHookOnlySandboxArtifacts(t *testing.T) {
	env := sandboxFile(t, sandboxArtifactsFor(t, NewHermesConnector(), "0.19.0"), HermesSandboxManagedEnvPath)
	for _, pin := range []string{"\nHERMES_SAFE_MODE=0\n", "\nHERMES_ENABLE_PROJECT_PLUGINS=0\n", "\nHERMES_ACCEPT_HOOKS=1\n", "\nTIRITH_ENABLED=0\n", "\nHERMES_DISABLE_LAZY_INSTALLS=1\n"} {
		if env.Owner != SandboxOwnerRoot || !strings.Contains(string(env.Data), pin) {
			t.Fatalf("managed env (%s) lacks %q:\n%s", env.Owner, pin, env.Data)
		}
	}
	for _, tc := range []struct {
		provider        SandboxArtifactProvider
		version         string
		canonical, user string
	}{
		{NewOpenHandsConnector(), "1.16.0", OpenHandsSandboxCanonicalHooksPath, OpenHandsSandboxHooksPath},
		{NewAntigravityConnector(), "1.2.12", AntigravitySandboxCanonicalHooksPath, AntigravitySandboxHooksPath},
	} {
		a := sandboxArtifactsFor(t, tc.provider, tc.version)
		c, u := sandboxFile(t, a, tc.canonical), sandboxFile(t, a, tc.user)
		if c.Owner != SandboxOwnerRoot || u.Owner != SandboxOwnerUser || string(c.Data) != string(u.Data) || len(c.Data) == 0 {
			t.Fatalf("%s canonical %s / user %s hooks differ", a.Connector, c.Owner, u.Owner)
		}
	}
}

func TestVerifyHermesSandboxManagedConfigRejectsTampering(t *testing.T) {
	rt, err := resolveSandboxTarget("hermes", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "0.19.0"})
	if err != nil {
		t.Fatal(err)
	}
	good, err := renderHermesSandboxManagedConfig(rt)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(fn func(map[string]interface{})) []byte {
		return tampered(t, good, yaml.Unmarshal, yaml.Marshal, fn)
	}
	hooks := func(d map[string]interface{}) map[string]interface{} { return d["hooks"].(map[string]interface{}) }
	assertTamperRejected(t, func(b []byte) error { return verifyHermesSandboxManagedConfig(b, rt) }, good, map[string][]byte{
		"missing-pre-tool-call": mutate(func(d map[string]interface{}) { delete(hooks(d), "pre_tool_call") }),
		"foreign-command": mutate(func(d map[string]interface{}) {
			hooks(d)["pre_tool_call"] = []interface{}{map[string]interface{}{"command": "/tmp/x.sh", "matcher": ".*", "timeout": 30}}
		}),
		"second-handler": mutate(func(d map[string]interface{}) {
			hooks(d)["on_session_start"] = append(hooks(d)["on_session_start"].([]interface{}), map[string]interface{}{"command": "/tmp/x.sh"})
		}),
		"auto-accept-off":   mutate(func(d map[string]interface{}) { d["hooks_auto_accept"] = false }),
		"plugins-enabled":   mutate(func(d map[string]interface{}) { d["plugins"] = map[string]interface{}{"enabled": []interface{}{"x"}} }),
		"plugins-unpinned":  mutate(func(d map[string]interface{}) { delete(d, "plugins") }),
		"remote-terminal":   mutate(func(d map[string]interface{}) { d["terminal"] = map[string]interface{}{"backend": "ssh"} }),
		"code-execution-on": mutate(func(d map[string]interface{}) { delete(d, "agent") }),
		"tirith-on": mutate(func(d map[string]interface{}) {
			d["security"] = map[string]interface{}{"tirith_enabled": true, "allow_lazy_installs": false}
		}),
		"lazy-installs-on":       mutate(func(d map[string]interface{}) { d["security"] = map[string]interface{}{"tirith_enabled": false} }),
		"model-catalog-on":       mutate(func(d map[string]interface{}) { d["model_catalog"] = map[string]interface{}{"enabled": true} }),
		"model-catalog-unpinned": mutate(func(d map[string]interface{}) { delete(d, "model_catalog") }),
		"provider-pinned-url": mutate(func(d map[string]interface{}) {
			d["providers"].(map[string]interface{})[HermesSandboxProviderName].(map[string]interface{})["base_url"] = "http://example.invalid/v1"
		}),
		"invalid-yaml": []byte("hooks: ["),
	})
}

// TestSandboxArtifactsSupported: every connector with an overlay variant
// reports it, and one without refuses to render (the docs capability matrix
// test checks the same set against the docs).
func TestSandboxArtifactsSupported(t *testing.T) {
	for _, tc := range sandboxGoldenTargets {
		if conn, ok := tc.provider.(Connector); !ok || !SandboxArtifactsSupported(conn) {
			t.Errorf("%s: sandbox artifacts not reported as supported", tc.connector)
		}
	}
	for _, conn := range []Connector{&hookOnlyConnector{name: "nosandbox"}, NewOpenClawConnector()} {
		if SandboxArtifactsSupported(conn) {
			t.Errorf("%s: reported as supported without a sandbox variant", conn.Name())
		}
		if provider, ok := conn.(SandboxArtifactProvider); ok {
			if _, err := provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: "1.0.0"}); err == nil ||
				!strings.Contains(err.Error(), "no OpenShell sandbox variant") {
				t.Errorf("%s: SandboxArtifacts error = %v", conn.Name(), err)
			}
		}
	}
}
