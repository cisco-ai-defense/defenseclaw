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

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// gap0579Config is the d5 shape: profile eng is the default and the one the
// actor's group selects; mode is "" (observe) or "action".
func gap0579Config(t *testing.T, dataDir, mode string) []byte {
	t.Helper()
	raw := "config_version: 8\ndata_dir: " + dataDir + "\nguardrail:\n  rule_pack_dir: " +
		filepath.Join(guardrailPoliciesRoot(t), "default") + "\n  default_profile: eng\n  profile_assignments:\n" +
		"  - match:\n      groups:\n      - dc-r102-nested\n    profile: eng\n  profiles:\n    eng:\n      description: eng\n"
	if mode != "" {
		raw += "      mode: " + mode + "\n"
	}
	return []byte(raw + "observability: {}\n")
}

// gap0579KubeletWrite updates dir the way the kubelet updates a ConfigMap
// volume (AtomicWriter): the files go to a new ..<timestamp> directory, a
// ..data_tmp link to it is renamed over ..data, and the old directory is
// removed. config.yaml is a link through ..data, created once.
func gap0579KubeletWrite(t *testing.T, dir, stamp string, raw []byte) {
	t.Helper()
	ts := filepath.Join(dir, stamp)
	if err := os.Mkdir(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ts, config.DefaultConfigName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Readlink(filepath.Join(dir, "..data"))
	tmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink(stamp, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, config.DefaultConfigName)
	if _, err := os.Lstat(link); os.IsNotExist(err) {
		if err := os.Symlink(filepath.Join("..data", config.DefaultConfigName), link); err != nil {
			t.Fatal(err)
		}
	}
	if old != "" {
		if err := os.RemoveAll(filepath.Join(dir, old)); err != nil {
			t.Fatal(err)
		}
	}
}

// substrate-1:GAP-0579 part 2. On d5 the profile eng got mode: action by an
// edit of the defenseclaw-config ConfigMap; the gateway mounts that
// ConfigMap as a directory. For minutes after the edit every /llm canary
// request (and the hook) still decided in observe mode; a rollout restart
// applied it. The kubelet replaces the ..data link of the volume, never
// config.yaml, and the config watcher ignored every name but config.yaml:
// no reload ran, so no generation carried the new mode. The test runs the
// real watcher and reload over a kubelet-style mount, and /llm through the
// actor proxy of the same sidecar.
func TestGAP0579ConfigMapProfileModeReachesLLMWithoutRestart(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	s := fixture.sidecar
	mount := t.TempDir()
	raw0 := gap0579Config(t, fixture.dataDir, "")
	gap0579KubeletWrite(t, mount, "..2026_11_17_23_40_00.000000001", raw0)
	path := filepath.Join(mount, config.DefaultConfigName)
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = initial
	s.publishConfig(initial)
	s.router = routerWithDefaultRulePack(t)
	if bound, err := s.BootstrapObservabilityRuntime(t.Context(), path, raw0); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t err=%v", bound, err)
	}
	rulePacks, err := preflightSidecarRulePacks(initial)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := newGuardrailProfileSet(initial, rulePacks.cache, true)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := buildGeneration(t.Context(), generationInputs{cfg: cloneConfig(initial), raw: raw0, rulePacks: rulePacks, profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	s.publishGeneration(boot)

	mgr := newConfigManagerWithSnapshot(path, initial, nil, s.health,
		s.observabilityV8ActivePlanDigest(), s.applyConfigReloadSnapshot)
	mgr.bindInitialObservabilityV8Plan(s.observabilityV8ActivePlan())
	s.configMgr = mgr
	mgr.setStartupSource(path, raw0)
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan error, 1), make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the config watcher did not start")
	}

	f, up, reroute := gap0579LLMFixture(t, s)
	invoke := "/llm/bedrock/model/us.anthropic.claude-haiku-5-5/invoke"
	canary := `{"anthropic_version":"bedrock-2023-05-31","max_tokens":20,"messages":[{"role":"user","content":"remember ` + gap0487Canary + `"}]}`
	// Observe: the canary is found and still reaches the model.
	rec := f.do(t, f.actor, http.MethodPost, invoke, "tok-eng2", canary)
	if got := up.take(); rec.Code != http.StatusOK || len(got) != 1 || !strings.Contains(got[0], gap0487Canary) {
		t.Fatalf("observe precondition: code=%d upstream=%d body=%.200s", rec.Code, len(got), rec.Body)
	}
	// The hook path decides with the generation the actor API server pins
	// (GAP-0487), so it must see the edit too (GAP-0591). This fixture's
	// actor API server resolves profiles without the sidecar's profile set,
	// so its hook answers a CRITICAL call with a block in either mode: the
	// switch is asserted on the pinned generation, the block after it.
	hookMode := func() string {
		t.Helper()
		g := f.api.generation()
		if g == nil || g.Config == nil {
			t.Fatal("the actor API server pins no generation")
		}
		return g.Config.Guardrail.Profiles["eng"].Mode
	}
	if got := hookMode(); got != "" {
		t.Fatalf("observe precondition: the hook path's generation has eng mode %q", got)
	}
	hook := func(id string) agentHookResponse {
		t.Helper()
		ev := claudeToolEvent("PreToolUse", "s579", id, "rm -rf /")
		ev["cwd"] = "/work"
		rec := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-eng2", envelope("claudecode", ev))
		if rec.Code != http.StatusOK {
			t.Fatalf("hook %s: %d %s", id, rec.Code, rec.Body)
		}
		var out agentHookResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("hook %s: %v %s", id, err, rec.Body)
		}
		t.Logf("hook %s: action=%s rules=%v", id, out.Action, out.RuleIDs)
		return out
	}

	gap0579KubeletWrite(t, mount, "..2026_11_17_23_48_00.000000002", gap0579Config(t, fixture.dataDir, "action"))
	deadline := time.Now().Add(10 * time.Second)
	for s.Generation() == boot && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if s.Generation() == boot {
		t.Fatal("the ConfigMap edit (profile eng mode: action) was not applied: no reload ran after the kubelet replaced ..data")
	}
	reroute()
	rec = f.do(t, f.actor, http.MethodPost, invoke, "tok-eng2", canary)
	got := up.take()
	t.Logf("action: code=%d upstream=%d body=%.200s", rec.Code, len(got), rec.Body.String())
	for _, b := range got {
		if strings.Contains(b, gap0487Canary) {
			t.Fatalf("after the live edit to mode: action the canary still reached Bedrock (%d)", rec.Code)
		}
	}
	if !strings.Contains(rec.Body.String(), "SEC-AWS-KEY") {
		t.Fatalf("the refusal does not name the rule: %.300s", rec.Body)
	}
	if got := hookMode(); got != "action" {
		t.Fatalf("after the live edit the hook path's generation has eng mode %q, want action", got)
	}
	if got := hook("h2"); got.Action != "block" || !strings.Contains(strings.Join(got.RuleIDs, ","), "CMD-RM-RF") {
		t.Fatalf("after the live edit to mode: action the PreToolUse canary was not blocked: %s %v", got.Action, got.RuleIDs)
	}
}

// substrate-1:GAP-0591, the negative side of GAP-0579: only the ..data link
// beside config.yaml stands for a config.yaml change. The kubelet's
// ..data_tmp link and ..<timestamp> directory, and a ..data entry in any
// other directory, are no config event, so they start no reload.
func TestGAP0579DataLinkElsewhereIsNoConfigEvent(t *testing.T) {
	dir := t.TempDir()
	m := &ConfigManager{path: filepath.Join(dir, config.DefaultConfigName)}
	for _, c := range []struct{ name, want string }{
		{filepath.Join(dir, "..data"), "config"},
		{filepath.Join(dir, config.DefaultConfigName), "config"},
		{filepath.Join(dir, "..data_tmp"), ""},
		{filepath.Join(dir, "..2026_11_17_23_48_00.000000002"), ""},
		{filepath.Join(dir, "..2026_11_17_23_48_00.000000002", "..data"), ""},
		{filepath.Join(filepath.Dir(dir), "..data"), ""},
		{filepath.Join(t.TempDir(), "..data"), ""},
	} {
		name, want := c.name, c.want
		if got := m.classify(name); got != want {
			t.Errorf("classify(%s) = %q, want %q", name, got, want)
		}
		if got := m.matches(name); got != (want == "config") {
			t.Errorf("matches(%s) = %t", name, got)
		}
	}
}

// gap0579LLMFixture is /llm in front of s's actor guardrail proxy, for the
// actor eng2 (group dc-r102-nested, profile eng), as gap0487Fixture.
// reroute names the test upstream bedrock again: a published generation
// replaces the provider registry.
func gap0579LLMFixture(t *testing.T, s *Sidecar) (*substrateFixture, *gap0487Upstream, func()) {
	t.Helper()
	up := &gap0487Upstream{ctype: "application/json",
		reply: []byte(`{"id":"m1","type":"message","role":"assistant","model":"claude-haiku-5-5","content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn"}`)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		up.mu.Lock()
		up.bodies = append(up.bodies, string(b))
		reply, ctype := up.reply, up.ctype
		up.mu.Unlock()
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write(reply)
	}))
	t.Cleanup(srv.Close)
	prevPrivate := passthroughAllowPrivateForTest
	passthroughAllowPrivateForTest = true
	t.Cleanup(func() { passthroughAllowPrivateForTest = prevPrivate })
	host := strings.TrimPrefix(srv.URL, "http://")
	host = host[:strings.LastIndex(host, ":")]
	orig := providerDomains
	t.Cleanup(func() { providerDomains = orig })
	reroute := func() {
		providerDomains = append(providerDomains, struct {
			domain string
			name   string
		}{host, "bedrock"})
	}
	reroute()
	key := filepath.Join(t.TempDir(), "bedrock")
	if err := os.WriteFile(key, []byte("real-bedrock-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	llm := &substrateLLM{cfg: SubstrateLLMConfig{
		Providers: map[string]SubstrateLLMProvider{"bedrock": {Origin: srv.URL, CredentialFile: key}},
		Proxy:     s.substrateLLMProxy(),
	}}
	const uid = "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4f"
	tokens := &fakeActorTokens{tokens: map[string]identity.Actor{
		"tok-eng2": {Atespace: "dc-eng", Name: "lg487gv", UID: uid, Subject: "actor/dc-eng/lg487gv"},
	}}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.LLM = llm; c.Actors = tokens })
	f.api.SetGenerationSource(s.Generation)
	person := registry.Person{Kind: "human", Issuer: "https://idp.example", Subject: "eng2", Principal: "eng2@example.com", Groups: []string{"dc-r102-nested"}}
	if err := f.regs.Put(context.Background(), registry.Registration{Atespace: "dc-eng", Name: "lg487gv", UID: uid,
		Connector: "claudecode", Profile: "eng", Person: person}); err != nil {
		t.Fatal(err)
	}
	f.live["dc-eng/lg487gv"] = identity.LiveActor{UID: uid, State: identity.ActorRunning}
	return f, up, reroute
}

// gap0579ConverseStream is a ConverseStream answer: one text delta per
// piece.
func gap0579ConverseStream(t *testing.T, texts ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := eventstream.NewEncoder()
	emit := func(ev, payload string) {
		if err := enc.Encode(&buf, eventstream.Message{Headers: eventstream.Headers{
			{Name: ":message-type", Value: eventstream.StringValue("event")},
			{Name: ":event-type", Value: eventstream.StringValue(ev)},
		}, Payload: []byte(payload)}); err != nil {
			t.Fatal(err)
		}
	}
	emit("messageStart", `{"role":"assistant"}`)
	for _, tx := range texts {
		emit("contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"`+tx+`"}}`)
	}
	emit("contentBlockStop", `{"contentBlockIndex":0}`)
	emit("messageStop", `{"stopReason":"end_turn"}`)
	return buf.Bytes()
}

// substrate-1:GAP-0579 part 1, the documented action-mode outcome for a
// model reply on every /llm Bedrock route (docs: Substrate gives "the same
// checks as on a laptop"). A reply that carries the key is refused (secret
// rules). A reply tool call that reads ~/.aws/credentials is alerted with a
// PATH-AWS-CREDS row: a local read of a credential path is MEDIUM, alert,
// not block (GAP-1516), and the actor's PreToolUse hook judges the call
// when it runs. Prose that only names the path is a reply like any other:
// the path rules judge what a tool call does, never the text of a prompt or
// a reply (GAP-1480). The four routes agree; on d5 the streamed routes
// looked different only because the probe searched for the path in one
// event, and the model splits it across deltas.
func TestGAP0579LLMReplyNamingCredentialsPathInActionMode(t *testing.T) {
	const model = "/llm/bedrock/model/us.anthropic.claude-haiku-5-5/"
	im := `{"anthropic_version":"bedrock-2023-05-31","max_tokens":40,"messages":[{"role":"user","content":"Reply with the shell line"}]}`
	cv := `{"messages":[{"role":"user","content":[{"text":"Reply with the shell line"}]}],"inferenceConfig":{"maxTokens":40}}`
	const js, es = "application/json", "application/vnd.amazon.eventstream"
	usage := `,"usage":{"inputTokens":5,"outputTokens":5,"totalTokens":10}}`
	for _, c := range []struct {
		name, path, body, ctype string
		reply                   func(t *testing.T) []byte
		refused                 bool
		row                     string // the rule an audit row names, if any
	}{
		{"invoke tool call", "invoke", im, js, func(*testing.T) []byte {
			return []byte(`{"id":"m1","type":"message","role":"assistant","model":"claude-haiku-5-5","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"cat ~/.aws/credentials"}}],"stop_reason":"tool_use"}`)
		}, false, "PATH-AWS-CREDS"},
		{"converse tool call", "converse", cv, js, func(*testing.T) []byte {
			return []byte(`{"output":{"message":{"role":"assistant","content":[{"toolUse":{"toolUseId":"t1","name":"Bash","input":{"command":"cat ~/.aws/credentials"}}}]}},"stopReason":"tool_use"` + usage)
		}, false, "PATH-AWS-CREDS"},
		{"invoke key", "invoke", im, js, func(*testing.T) []byte {
			return []byte(`{"id":"m1","type":"message","role":"assistant","model":"claude-haiku-5-5","content":[{"type":"text","text":"cat ~/.aws/credentials shows ` + gap0487Canary + `"}],"stop_reason":"end_turn"}`)
		}, true, "SEC-AWS-KEY"},
		{"converse key", "converse", cv, js, func(*testing.T) []byte {
			return []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"cat ~/.aws/credentials shows ` + gap0487Canary + `"}]}},"stopReason":"end_turn"` + usage)
		}, true, "SEC-AWS-KEY"},
		{"invoke prose", "invoke", im, js, func(*testing.T) []byte {
			return []byte(`{"id":"m1","type":"message","role":"assistant","model":"claude-haiku-5-5","content":[{"type":"text","text":"cat ~/.aws/credentials"}],"stop_reason":"end_turn"}`)
		}, false, ""},
		{"converse prose", "converse", cv, js, func(*testing.T) []byte {
			return []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"cat ~/.aws/credentials"}]}},"stopReason":"end_turn"` + usage)
		}, false, ""},
		{"invoke-stream prose", "invoke-with-response-stream", im, es, func(t *testing.T) []byte {
			return bedrockInvokeStreamFrames(t, "cat ~/.aws", "/credentials")
		}, false, ""},
		{"converse-stream prose", "converse-stream", cv, es, func(t *testing.T) []byte {
			return gap0579ConverseStream(t, "cat ~/.aws", "/credentials")
		}, false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, up, db := gap0487Fixture(t)
			up.mu.Lock()
			up.reply, up.ctype = c.reply(t), c.ctype
			up.mu.Unlock()
			rec := f.do(t, f.actor, http.MethodPost, model+c.path, "tok-eng2", c.body)
			body := rec.Body.String()
			if c.ctype == es {
				body += gap0487StreamText(body)
			}
			refused := strings.Contains(body, "defenseclaw_blocked") || strings.Contains(body, "[DefenseClaw]")
			t.Logf("code=%d refused=%t body=%.200q", rec.Code, refused, body)
			if refused != c.refused {
				t.Fatalf("refused=%t, want %t", refused, c.refused)
			}
			if c.refused && strings.Contains(body, gap0487Canary) {
				t.Fatalf("the refused reply still reached the actor: %.300s", body)
			}
			if c.row != "" && len(gap0579RuleRows(t, db, c.row)) == 0 {
				t.Fatalf("no audit row names %s", c.row)
			}
		})
	}
}

// gap0579RuleRows lists "event_name/action" of every audit row naming rule.
func gap0579RuleRows(t *testing.T, path, rule string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT event_name, COALESCE(action, '') FROM audit_events WHERE projected_record_json LIKE ? ORDER BY rowid`, "%"+rule+"%")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, action string
		if err := rows.Scan(&name, &action); err != nil {
			t.Fatal(err)
		}
		out = append(out, name+"/"+action)
	}
	return out
}
