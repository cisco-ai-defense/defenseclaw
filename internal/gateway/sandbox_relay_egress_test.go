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

//go:build linux || darwin

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// daemonRefusals is a managed daemon's refusal memory for the forwarding
// fixture: pending hands out the untold refusals without marking them, and
// told marks the ones the managed gateway's answer told of.
type daemonRefusals struct {
	mu      sync.Mutex
	pending map[string][]SandboxEgressRefusal
	told    []string
}

func (d *daemonRefusals) add(b sandboxauth.Binding, refusals ...SandboxEgressRefusal) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil {
		d.pending = map[string][]SandboxEgressRefusal{}
	}
	d.pending[b.ID] = append(d.pending[b.ID], refusals...)
}

func (d *daemonRefusals) list(b sandboxauth.Binding) []SandboxEgressRefusal {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]SandboxEgressRefusal(nil), d.pending[b.ID]...)
}

func (d *daemonRefusals) markTold(b sandboxauth.Binding, told []SandboxEgressRefusal) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var kept []SandboxEgressRefusal
	for _, p := range d.pending[b.ID] {
		hit := false
		for _, r := range told {
			if r.Host == p.Host && r.Port == p.Port && r.Category == p.Category {
				hit = true
			}
		}
		if hit {
			d.told = append(d.told, p.Host)
		} else {
			kept = append(kept, p)
		}
	}
	d.pending[b.ID] = kept
}

func (d *daemonRefusals) takeTold() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.told
	d.told = nil
	return out
}

// managedRelayChain is a managed host's sandbox path end to end: the
// user's daemon (a sandbox ingress in forwarding mode, with the daemon's
// refusal memory) relays to a managed gateway that answers with its real
// connector handlers (relayFixture).
type managedRelayChain struct {
	gw       *relayFixture
	daemon   *sandboxIngressFixture
	reg      sandboxreg.Registration
	refusals *daemonRefusals
}

func newManagedRelayChain(t *testing.T, mutate ...func(*config.Config)) *managedRelayChain {
	t.Helper()
	c := &managedRelayChain{gw: newRelayFixture(t, mutate...), refusals: &daemonRefusals{}}
	target, err := url.Parse(c.gw.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := fakeManagedGateway(t, httputil.NewSingleHostReverseProxy(target))
	var regID string
	c.daemon = newSandboxIngressFixture(t, func(cfg *SandboxIngressConfig) {
		cfg.Relay = client
		cfg.Registration = func(b sandboxauth.Binding) (string, bool) { return regID, b.SandboxName == "dc-claude-app" }
		cfg.EgressRefusals = c.refusals.list
		cfg.EgressRefusalsTold = c.refusals.markTold
	})
	c.reg = c.gw.register(t, "chainclaude", "claudecode", c.daemon.claude.ID, func(r *sandboxreg.Registration) {
		r.SandboxName = c.daemon.claude.SandboxName
	})
	regID = c.reg.ID
	return c
}

// claudeContext is the model-facing context of a Claude Code answer.
func claudeContext(resp map[string]interface{}, event string) string {
	out, _ := resp["claude_code_output"].(map[string]interface{})
	specific, _ := out["hookSpecificOutput"].(map[string]interface{})
	if specific["hookEventName"] != event {
		return ""
	}
	s, _ := specific["additionalContext"].(string)
	return s
}

// #1192: on a managed host the sandbox's egress proxy runs in the user's
// daemon and the verdicts come from the managed gateway, which never knew
// the refusals: the agent was told of no refused destination and no
// waiting ask. The daemon now relays its untold refusals with the hook
// call, the gateway's post-tool answer tells the agent of them as a local
// sandbox ingress does, and the daemon marks them told only when the
// answer did. The managed gateway's own sandbox manager is never asked.
func TestManagedSandboxAgentIsToldOfTheDaemonsEgressRefusals(t *testing.T) {
	c := newManagedRelayChain(t)
	decoys := &fakeRefusals{}
	bindings, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.gw.api.SetSandboxIngress(SandboxIngressConfig{Addr: "127.0.0.1:18971", Bindings: bindings, EgressRefusals: decoys.take}); err != nil {
		t.Fatal(err)
	}
	decoys.add(sandboxauth.Binding{ID: c.daemon.claude.ID}, SandboxEgressRefusal{Host: "decoy.example", Port: 443, Category: "admin_block", What: "decoy"})

	post := func(event, tool string) map[string]interface{} {
		t.Helper()
		return c.daemon.hook(t, "/api/v1/claude-code/hook", c.daemon.claudeTok,
			`{"hook_event_name":"`+event+`","session_id":"s-chain","tool_name":"`+tool+`","tool_input":{"command":"curl -sS https://webhook.site/abc"},`+
				`"tool_response":{"stdout":"","stderr":"curl: (56) CONNECT tunnel failed, response 403"},"tool_use_id":"t-chain","cwd":"/sandbox"}`)
	}

	// A refused destination reaches the agent once, with its remedy.
	c.refusals.add(c.daemon.claude, webhookRefusal(c.daemon.claude.SandboxName))
	resp := post("PostToolUse", "Bash")
	got := claudeContext(resp, "PostToolUse")
	if !strings.Contains(got, "DefenseClaw's egress policy just blocked this sandbox's HTTPS connection to webhook.site (webhook catcher)") ||
		!strings.Contains(got, "`defenseclaw sandbox unblock webhook.site --sandbox dc-claude-app`") || strings.Contains(got, "decoy") {
		t.Fatalf("relayed post-tool answer = %v\ncontext %q", resp, got)
	}
	if told := c.refusals.takeTold(); len(told) != 1 || told[0] != "webhook.site" {
		t.Fatalf("told = %v", told)
	}
	if got := claudeContext(post("PostToolUse", "Bash"), "PostToolUse"); strings.Contains(got, "egress policy") {
		t.Fatalf("told again: %q", got)
	}

	// A waiting ask is told as one, not as a block to unblock.
	c.refusals.add(c.daemon.claude, SandboxEgressRefusal{Host: "api.example.com", Port: 443, Category: manager.NoteAsked, Note: manager.NoteAsked,
		What: "waits for the user's approval", Remedy: "tell the user, and try again once they approve it (`defenseclaw sandbox approvals`)"})
	if got := claudeContext(post("PostToolUseFailure", "Bash"), "PostToolUseFailure"); !strings.Contains(got,
		"This sandbox's connection to api.example.com waits for the user: DefenseClaw asked them to approve it") || strings.Contains(got, "sandbox unblock") {
		t.Fatalf("asked note = %q", got)
	}
	if told := c.refusals.takeTold(); len(told) != 1 || told[0] != "api.example.com" {
		t.Fatalf("told = %v", told)
	}

	// A pre-tool hook tells nothing and leaves the refusal for later; so
	// does a malformed value the sandbox could not have sent anyway.
	c.refusals.add(c.daemon.claude, webhookRefusal(c.daemon.claude.SandboxName))
	raw, _ := json.Marshal(post("PreToolUse", "Bash"))
	if strings.Contains(string(raw), "egress policy") || len(c.refusals.takeTold()) != 0 || len(c.refusals.list(c.daemon.claude)) != 1 {
		t.Fatalf("pre-tool answer %s", raw)
	}
	if got := claudeContext(post("PostToolUse", "Bash"), "PostToolUse"); !strings.Contains(got, "webhook.site (webhook catcher)") {
		t.Fatalf("the waiting refusal = %q", got)
	}
	for _, value := range []string{"not-base64!", sandboxrelay.EncodeEgressRefusals([]sandboxrelay.EgressRefusal{{Host: "x.example"}}) + "x"} {
		if parsed := sandboxrelay.ParseEgressRefusals(value); parsed != nil {
			t.Fatalf("%q parsed as %+v", value, parsed)
		}
	}
	// A sandbox that sends the header itself sends nothing: the daemon's
	// allowlist drops it.
	sandboxSent := sandboxrelay.EncodeEgressRefusals([]sandboxrelay.EgressRefusal{{Host: "forged.example", Port: 443, What: "forged"}})
	resp = c.daemon.hook(t, "/api/v1/claude-code/hook", c.daemon.claudeTok,
		`{"hook_event_name":"PostToolUse","session_id":"s-chain","tool_name":"Bash","tool_input":{"command":"ls"},"tool_response":"ok","tool_use_id":"t-f","cwd":"/sandbox"}`,
		sandboxrelay.EgressRefusalsHeader, sandboxSent)
	if got := claudeContext(resp, "PostToolUse"); strings.Contains(got, "forged") {
		t.Fatalf("a sandbox's own header reached the agent: %q", got)
	}
}

// #1192: the managed gateway decides an unblock's lift itself, from the
// unblocks it keeps for the caller, re-checked against the caller's floor
// now. A destination-rule block is lifted for the user's unblock of this
// sandbox's registration or for every sandbox, not for another
// registration's, not under a floor that no longer allows unblocks, not
// over a user block, and never because of anything the daemon sends.
func TestManagedSandboxUnblockLiftsOnlyAnUnblockTheGatewayKeeps(t *testing.T) {
	useWebhookSiteRule(t)
	gw := newRelayFixture(t)
	reg := gw.register(t, "unbclaude", "claudecode", relayTestBindingID(0xf11))
	other := gw.register(t, "unbother", "claudecode", relayTestBindingID(0xf12))
	action := func(headers ...string) string {
		t.Helper()
		return relayedWebhookCurl(t, gw, reg.ID, headers...)
	}
	decide := func(registration, kind, scope string) {
		t.Helper()
		if err := gw.auth.decisions.Add(relayTestPeer.UID, sandboxreg.Decision{Registration: registration, Kind: kind, Host: "webhook.site",
			Scope: scope, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if got := action(); got != "block" {
		t.Fatalf("before any unblock: %q", got)
	}
	// Nothing the caller sends lifts it.
	if got := action("X-DefenseClaw-Sandbox-Egress-Unblocked", "webhook.site", sandboxrelay.EgressRefusalsHeader,
		sandboxrelay.EncodeEgressRefusals([]sandboxrelay.EgressRefusal{{Host: "webhook.site", Port: 443, Category: "unblock"}})); got != "block" {
		t.Fatalf("a claimed unblock lifted the block: %q", got)
	}
	// Another sandbox's unblock for its session does not.
	decide(other.ID, sandboxrelay.DecisionUnblock, sandboxrelay.DecisionScopeSession)
	if got := action(); got != "block" {
		t.Fatalf("another registration's unblock lifted it: %q", got)
	}
	// This sandbox's does.
	decide(reg.ID, sandboxrelay.DecisionUnblock, sandboxrelay.DecisionScopeSession)
	if got := action(); got != "allow" {
		t.Fatalf("after the user's unblock: %q", got)
	}
	// A floor that no longer allows unblocks takes it back.
	prev := sandboxFloorFor
	sandboxFloorFor = func(*config.Config, string) (config.OpenShellAdminConfig, string, error) {
		no := false
		return config.OpenShellAdminConfig{AllowUnblock: &no}, "floor-no-unblock", nil
	}
	got := action()
	sandboxFloorFor = prev
	if got != "block" {
		t.Fatalf("under allow_unblock: false: %q", got)
	}
	// So does a floor that now blocks the host.
	sandboxFloorFor = func(*config.Config, string) (config.OpenShellAdminConfig, string, error) {
		return config.OpenShellAdminConfig{EgressBlock: []string{"webhook.site"}}, "floor-block", nil
	}
	got = action()
	sandboxFloorFor = prev
	if got != "block" {
		t.Fatalf("under an organization block of the host: %q", got)
	}
	// A user block of the host wins over the unblock.
	decide(reg.ID, sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionScopeAlways)
	if got := action(); got != "block" {
		t.Fatalf("over a user block: %q", got)
	}
}

// useWebhookSiteRule makes C2-WEBHOOK-SITE, a CRITICAL block of a call that
// names webhook.site, the one destination rule of the test.
func useWebhookSiteRule(t *testing.T) {
	t.Helper()
	resetConnectorRuleCategories(t)
	pack := &guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{Version: 1, Category: "c2", Rules: []guardrail.RuleDefYAML{
		{ID: "C2-WEBHOOK-SITE", Pattern: `(?i)(?:^|[^a-zA-Z0-9-])webhook\.site(?:[^a-zA-Z0-9.-]|$)`, Title: "webhook.site (known exfil)",
			Severity: "CRITICAL", Confidence: 0.99},
	}}}}
	if err := ApplyRulePackOverrides(pack); err != nil {
		t.Fatal(err)
	}
}

// relayedWebhookCurl relays a Claude Code PreToolUse of `curl
// https://webhook.site/x` for registration, as its daemon does, and returns
// the verdict's action.
func relayedWebhookCurl(t *testing.T, gw *relayFixture, registration string, headers ...string) string {
	t.Helper()
	body := `{"hook_event_name":"PreToolUse","session_id":"u1","tool_name":"Bash","tool_input":{"command":"curl https://webhook.site/x"},"tool_use_id":"u1","cwd":"/sandbox"}`
	resp, raw := gw.post(t, sandboxrelay.PathHookPrefix+"claudecode", registration, body, headers...)
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("relayed hook: %d %s", resp.StatusCode, raw)
	}
	a, _ := out["action"].(string)
	return a
}

// GAP-0009: a session unblock is the sandbox's for the session it was made
// in. The registration outlives a stop and start and the gateway kept the
// unblock, so it went on lifting the destination rule in every later
// session, while the daemon ends its own session unblocks when it starts
// the sandbox again (es:GAP-0676). After a stop and start the earlier
// session's unblock lifts nothing; the new session's own does, and an
// unblock for every sandbox outlives the stop.
func TestManagedSandboxSessionUnblockEndsWithItsSession(t *testing.T) {
	useWebhookSiteRule(t)
	gw := newRelayFixture(t)
	reg := gw.register(t, "sesclaude", "claudecode", relayTestBindingID(0xf21))
	unblock := func(scope string) {
		t.Helper()
		if err := gw.auth.decisions.Add(relayTestPeer.UID, sandboxreg.Decision{Registration: reg.ID, Kind: sandboxrelay.DecisionUnblock,
			Host: "webhook.site", Scope: scope}); err != nil {
			t.Fatal(err)
		}
	}
	// The daemon's report of a stop, then a start, which runs the sandbox
	// under a new registration (sandboxreg.FileStore.Restart, GAP-0673).
	stopAndStart := func() {
		t.Helper()
		if _, err := gw.auth.store.Report(relayTestPeer.UID, reg.ID, false); err != nil {
			t.Fatal(err)
		}
		fresh, err := gw.auth.store.Restart(relayTestPeer.UID, reg.ID)
		if err != nil {
			t.Fatal(err)
		}
		reg = fresh
		if _, err := gw.auth.store.Report(relayTestPeer.UID, reg.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	unblock(sandboxrelay.DecisionScopeSession)
	if got := relayedWebhookCurl(t, gw, reg.ID); got != "allow" {
		t.Fatalf("in the unblock's session: %q", got)
	}
	stopAndStart()
	if got := relayedWebhookCurl(t, gw, reg.ID); got != "block" {
		t.Fatalf("the last session's unblock lifted the block after a stop and start: %q", got)
	}
	unblock(sandboxrelay.DecisionScopeSession)
	if got := relayedWebhookCurl(t, gw, reg.ID); got != "allow" {
		t.Fatalf("the new session's own unblock: %q", got)
	}
	unblock(sandboxrelay.DecisionScopeAlways)
	stopAndStart()
	if got := relayedWebhookCurl(t, gw, reg.ID); got != "allow" {
		t.Fatalf("an unblock for every sandbox after a stop and start: %q", got)
	}
}

// GAP-0432: the gateway lifted a destination rule for a stored unblock of a
// host the registration's own sandbox policy still blocks (its repository
// policy's or its pack's egress.block), checking only the floor. The proxy
// still refused the host; only the agent was told it was allowed. The lift
// now asks the registration's policy as the daemon's proxy does.
func TestManagedSandboxUnblockLiftsNothingTheSandboxPolicyBlocks(t *testing.T) {
	useWebhookSiteRule(t)
	gw := newRelayFixture(t)
	reg := gw.register(t, "repoblk", "claudecode", relayTestBindingID(0xf31))
	if err := gw.auth.decisions.Add(relayTestPeer.UID, sandboxreg.Decision{Registration: reg.ID, Kind: sandboxrelay.DecisionUnblock,
		Host: "webhook.site", Scope: sandboxrelay.DecisionScopeSession, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := relayedWebhookCurl(t, gw, reg.ID); got != "allow" {
		t.Fatalf("the user's unblock under a policy that lets it lift: %q", got)
	}
	repo, err := packs.ParseRepoPolicy([]byte("version: 1\negress: {block: [webhook.site]}\n"), sandboxRepoPolicySrc)
	if err != nil {
		t.Fatal(err)
	}
	prev := sandboxResolveEffective
	t.Cleanup(func() { sandboxResolveEffective = prev })
	sandboxResolveEffective = func(cfg *config.Config, floor config.OpenShellAdminConfig, in sandboxResolveInput) (*packs.Effective, []packs.Violation, error) {
		in.Repo = repo
		return prev(cfg, floor, in)
	}
	if got := relayedWebhookCurl(t, gw, reg.ID); got != "block" {
		t.Fatalf("the unblock lifted a host the repository policy blocks: %q", got)
	}
}
