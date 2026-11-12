// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

const substrateTestHost = "defenseclaw-actor.defenseclaw-system.svc.cluster.local"

func substrateRender(t *testing.T, c SandboxArtifactProvider, version string) SandboxArtifacts {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sandbox artifacts render on Linux and macOS hosts")
	}
	in := &SandboxIngress{Runtime: sandboxruntime.Substrate, Host: substrateTestHost, Port: 443, Scheme: "https",
		CAFile: "/run/ate/trust-bundle.pem", ActorHeader: true}
	art, err := c.SandboxArtifacts(SandboxRenderTarget{Ingress: in, FailMode: SandboxFailMode, AgentVersion: version, OtelEnvironment: "substrate"})
	if err != nil {
		t.Fatal(err)
	}
	return art
}

func artifactFile(art SandboxArtifacts, suffix string) string {
	for _, f := range art.Files {
		if strings.HasSuffix(f.Path, suffix) {
			return string(f.Data)
		}
	}
	return ""
}

// Under Substrate every side transport sends the actor header placeholder
// and no bearer, to the actor Service by its bare name.
func TestSubstrateSideTransports(t *testing.T) {
	cc := substrateRender(t, NewClaudeCodeConnector(), "2.1.156")
	helper := artifactFile(cc, "/otel-headers.sh")
	if !strings.Contains(helper, `"`+SandboxActorHeader+`":"`+SandboxActorPlaceholder+`"`) || strings.Contains(helper, "Authorization") ||
		strings.Contains(helper, SandboxTokenEnv) {
		t.Fatalf("Claude otelHeadersHelper:\n%s", helper)
	}
	dropIn := artifactFile(cc, "50-defenseclaw.json")
	if !strings.Contains(dropIn, `"https://`+substrateTestHost+`/v1/logs"`) || strings.Contains(dropIn, SandboxIngressHost) || strings.Contains(dropIn, ":443") {
		t.Fatalf("Claude OTLP endpoints are not the actor Service:\n%s", dropIn)
	}

	cx := substrateRender(t, NewCodexConnector(), "0.146.0")
	notify := artifactFile(cx, "/codex-notify.sh")
	for _, want := range []string{"'https://" + substrateTestHost + "/api/v1/substrate/notify/codex'", SandboxActorHeader + ": " + SandboxActorPlaceholder,
		"--cacert '/run/ate/trust-bundle.pem'", `"v":"1","connector":"codex"`} {
		if !strings.Contains(notify, want) {
			t.Errorf("Codex notify bridge lacks %q:\n%s", want, notify)
		}
	}
	if strings.Contains(notify, "Authorization") || strings.Contains(notify, SandboxTokenEnv) {
		t.Fatalf("Codex notify bridge sends a bearer:\n%s", notify)
	}
	mc := artifactFile(cx, "managed_config.toml")
	if !strings.Contains(mc, "endpoint = 'https://"+substrateTestHost+"/v1/logs'") ||
		strings.Count(mc, SandboxActorHeader+" = '"+SandboxActorPlaceholder+"'") != 3 || strings.Contains(mc, SandboxIngressHost) {
		t.Fatalf("Codex OTLP exporters:\n%s", mc)
	}
}

// OpenShell renders keep the binding token on every side transport.
func TestOpenShellSideTransportsUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sandbox artifacts render on Linux and macOS hosts")
	}
	art, err := NewCodexConnector().SandboxArtifacts(SandboxRenderTarget{IngressPort: 18970, FailMode: SandboxFailMode, AgentVersion: "0.146.0"})
	if err != nil {
		t.Fatal(err)
	}
	notify := artifactFile(art, "/codex-notify.sh")
	if !strings.Contains(notify, "http://"+SandboxIngressHost+":18970/api/v1/codex/notify") || strings.Contains(notify, SandboxActorHeader) {
		t.Fatalf("OpenShell notify bridge changed:\n%s", notify)
	}
	if strings.Contains(artifactFile(art, "managed_config.toml"), SandboxActorHeader) {
		t.Fatal("OpenShell OTLP exporters send the actor header")
	}
}

// The OpenCode plugin of a Substrate render holds no token and opens no
// connection: it execs the kit's hook-post. Amp's plugin has no such
// variant, so its Substrate render stays refused. OpenShell renders keep
// the binding-token post.
func TestSubstratePluginTransport(t *testing.T) {
	oc := substrateRender(t, NewOpenCodeConnector(), "2.1.4")
	plugin := artifactFile(oc, "/opencode/index.js")
	for _, want := range []string{SandboxSubstrateHookBinary, `["hook-post"]`, `/api/v1/opencode/hook`, "sandbox hooks always fail closed"} {
		if !strings.Contains(plugin, want) {
			t.Errorf("OpenCode Substrate plugin lacks %q", want)
		}
	}
	for _, bad := range []string{SandboxTokenEnv, "fetch(", "http://", "{{"} {
		if strings.Contains(plugin, bad) {
			t.Errorf("OpenCode Substrate plugin contains %q", bad)
		}
	}
	if env := oc.Env[SandboxTokenEnv]; env != SandboxSubstrateTokenPlaceholder {
		t.Errorf("OpenCode env %s = %q", SandboxTokenEnv, env)
	}

	in := &SandboxIngress{Runtime: sandboxruntime.Substrate, Host: substrateTestHost, Port: 443, Scheme: "https", ActorHeader: true}
	if _, err := NewAMPConnector().SandboxArtifacts(SandboxRenderTarget{Ingress: in, AgentVersion: "0.0.1785334225-g9abe75"}); err == nil ||
		!strings.Contains(err.Error(), "no Agent Substrate transport") {
		t.Errorf("Amp rendered for Substrate: %v", err)
	}

	openshell, err := NewOpenCodeConnector().SandboxArtifacts(SandboxRenderTarget{IngressPort: 18970, FailMode: SandboxFailMode, AgentVersion: "2.1.4"})
	if err != nil {
		t.Fatal(err)
	}
	osPlugin := artifactFile(openshell, "/opencode/index.js")
	if !strings.Contains(osPlugin, SandboxTokenEnv) || strings.Contains(osPlugin, "hook-post") {
		t.Error("OpenShell OpenCode plugin changed")
	}
}
