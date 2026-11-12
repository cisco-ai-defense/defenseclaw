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
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

const testSubstrateActorHost = "defenseclaw-actor.defenseclaw-system.svc"

func substrateIngress() *SandboxIngress {
	return &SandboxIngress{Runtime: sandboxruntime.Substrate, Host: testSubstrateActorHost, Port: 443, ActorHeader: true}
}

// Without an ingress a target is the OpenShell ingress, exactly as before.
func TestResolveIngressDefaultsToOpenShell(t *testing.T) {
	for _, target := range []SandboxRenderTarget{
		{IngressPort: 18971},
		{Ingress: &SandboxIngress{Port: 18971}},
		{IngressPort: 18971, Ingress: &SandboxIngress{Runtime: "openshell", Host: SandboxIngressHost, Port: 18971, Scheme: "http"}},
	} {
		in, err := target.ResolveIngress()
		if err != nil {
			t.Fatalf("%+v: %v", target, err)
		}
		want := SandboxIngress{Runtime: sandboxruntime.OpenShell, Host: "host.openshell.internal", Port: 18971, Scheme: "http"}
		if in != want {
			t.Fatalf("%+v resolved %+v, want %+v", target, in, want)
		}
		if in.Addr() != "host.openshell.internal:18971" || in.URL("/x") != "http://host.openshell.internal:18971/x" || in.Substrate() {
			t.Fatalf("addr %q url %q substrate %t", in.Addr(), in.URL("/x"), in.Substrate())
		}
	}
}

func TestResolveIngressRefusals(t *testing.T) {
	for name, target := range map[string]SandboxRenderTarget{
		"no port":                {},
		"port range":             {IngressPort: 70000},
		"contradicting ports":    {IngressPort: 18971, Ingress: &SandboxIngress{Port: 18972}},
		"unknown runtime":        {Ingress: &SandboxIngress{Runtime: "kata", Port: 1}},
		"openshell other host":   {Ingress: &SandboxIngress{Host: "gateway.example", Port: 1}},
		"openshell https":        {Ingress: &SandboxIngress{Port: 1, Scheme: "https"}},
		"openshell actor header": {Ingress: &SandboxIngress{Port: 1, ActorHeader: true}},
		"bad scheme":             {Ingress: &SandboxIngress{Runtime: "substrate", Host: testSubstrateActorHost, Port: 1, Scheme: "ftp", ActorHeader: true}},
		"substrate no host":      {Ingress: &SandboxIngress{Runtime: "substrate", Port: 443, ActorHeader: true}},
		"substrate alias host":   {Ingress: &SandboxIngress{Runtime: "substrate", Host: "host.openshell.internal", Port: 443, ActorHeader: true}},
		"substrate no header":    {Ingress: &SandboxIngress{Runtime: "substrate", Host: testSubstrateActorHost, Port: 443}},
		"substrate uppercase":    {Ingress: &SandboxIngress{Runtime: "substrate", Host: "Actor.svc", Port: 443, ActorHeader: true}},
		"substrate shell chars":  {Ingress: &SandboxIngress{Runtime: "substrate", Host: "a$(id).svc", Port: 443, ActorHeader: true}},
		"substrate ip literal":   {Ingress: &SandboxIngress{Runtime: "substrate", Host: "[::1]", Port: 443, ActorHeader: true}},
		"substrate label hyphen": {Ingress: &SandboxIngress{Runtime: "substrate", Host: "-a.svc", Port: 443, ActorHeader: true}},
		"ca without https":       {Ingress: &SandboxIngress{Runtime: "substrate", Host: testSubstrateActorHost, Port: 80, CAFile: "/etc/ca.pem", ActorHeader: true}},
		"ca relative":            {Ingress: &SandboxIngress{Runtime: "substrate", Host: testSubstrateActorHost, Port: 443, Scheme: "https", CAFile: "ca.pem", ActorHeader: true}},
		"ca unclean":             {Ingress: &SandboxIngress{Runtime: "substrate", Host: testSubstrateActorHost, Port: 443, Scheme: "https", CAFile: "/etc/../ca.pem", ActorHeader: true}},
		"ca newline":             {Ingress: &SandboxIngress{Runtime: "substrate", Host: testSubstrateActorHost, Port: 443, Scheme: "https", CAFile: "/etc/ca\n.pem", ActorHeader: true}},
	} {
		if in, err := target.ResolveIngress(); err == nil {
			t.Errorf("%s: resolved %+v", name, in)
		}
	}
}

func TestResolveIngressSubstrate(t *testing.T) {
	in, err := SandboxRenderTarget{Ingress: &SandboxIngress{
		Runtime: "substrate", Host: testSubstrateActorHost, Port: 443, Scheme: "https",
		CAFile: "/var/run/ate/ca.pem", ActorHeader: true,
	}}.ResolveIngress()
	if err != nil {
		t.Fatal(err)
	}
	if !in.Substrate() || in.URL("/api/v1/claude-code/hook") != "https://"+testSubstrateActorHost+":443/api/v1/claude-code/hook" {
		t.Fatalf("resolved %+v url %q", in, in.URL("/api/v1/claude-code/hook"))
	}
}

// An OpenShell target that names its ingress renders exactly what the bare
// port renders, for every golden connector.
func TestExplicitOpenShellIngressRendersTheSameBytes(t *testing.T) {
	for _, tc := range sandboxGoldenTargets {
		bare := renderSandboxGolden(t, tc.provider, tc.version)
		named, err := tc.provider.SandboxArtifacts(SandboxRenderTarget{
			Ingress: &SandboxIngress{Runtime: "openshell", Port: 18971}, AgentVersion: tc.version,
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.connector, err)
		}
		if len(bare.Files) != len(named.Files) {
			t.Fatalf("%s: %d files, want %d", tc.connector, len(named.Files), len(bare.Files))
		}
		for i := range bare.Files {
			if bare.Files[i].Path != named.Files[i].Path || !bytes.Equal(bare.Files[i].Data, named.Files[i].Data) {
				t.Fatalf("%s: %s differs", tc.connector, bare.Files[i].Path)
			}
		}
		if _, set := named.Env[SandboxTokenEnv]; set {
			t.Fatalf("%s: OpenShell env carries %s", tc.connector, SandboxTokenEnv)
		}
	}
}

// A Substrate render bakes the actor Service, carries the token placeholder
// in its env and never the OpenShell host in its transport.
func TestSubstrateRenderBakesTheActorIngress(t *testing.T) {
	for _, tc := range sandboxGoldenTargets {
		artifacts, err := tc.provider.SandboxArtifacts(SandboxRenderTarget{Ingress: substrateIngress(), AgentVersion: tc.version})
		if _, shell := sandboxHookScriptsByConnector[tc.connector]; !shell {
			if err == nil || !strings.Contains(err.Error(), "no Agent Substrate transport") {
				t.Fatalf("%s: plugin transport rendered for Substrate: %v", tc.connector, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.connector, err)
		}
		if artifacts.Env[SandboxTokenEnv] != SandboxSubstrateTokenPlaceholder {
			t.Fatalf("%s: env %s = %q", tc.connector, SandboxTokenEnv, artifacts.Env[SandboxTokenEnv])
		}
		transport := string(sandboxFile(t, artifacts, SandboxHookDir+"/_sandbox.sh").Data)
		for _, want := range []string{
			`readonly DC_SANDBOX_INGRESS="` + testSubstrateActorHost + `:443"`,
			`curl_args+=(-H 'x-defenseclaw-actor: defenseclaw-actor-placeholder')`,
			`"http://${DC_SANDBOX_INGRESS}${path}" \`,
		} {
			if !strings.Contains(transport, want) {
				t.Fatalf("%s: _sandbox.sh lacks %q", tc.connector, want)
			}
		}
		if strings.Contains(transport, "{{") || strings.Contains(transport, "host.openshell.internal, relayed") {
			t.Fatalf("%s: _sandbox.sh keeps OpenShell transport text", tc.connector)
		}
	}
}

func TestSubstrateRenderRefusesATokenFromTheConnector(t *testing.T) {
	rt, err := resolveSandboxTarget("claudecode", SandboxRenderTarget{Ingress: substrateIngress(), AgentVersion: "2.1.156"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finalizeSandboxArtifactsFor(rt, SandboxArtifacts{Env: map[string]string{SandboxTokenEnv: "x"}}); err == nil {
		t.Fatal("a connector-set token env was accepted")
	}
}
