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
	"context"
	"database/sql"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// gap0487Canary is an AWS access key id shape (AKIA + 16), not a real key.
const gap0487Canary = "AKIAJ3Q7XK2M9WPLN4RT"

type gap0487Upstream struct {
	mu     sync.Mutex
	bodies []string
	reply  []byte
	ctype  string
}

func (u *gap0487Upstream) take() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	b := u.bodies
	u.bodies = nil
	return b
}

// gap0487Gen is a published configuration generation: a default profile eng
// with no mode (observe), and, when withAct, the lane's action-mode profile
// j04-act for the group dc-r102-nested, as on E1.
func gap0487Gen(t *testing.T, withAct bool, n uint64) (*Generation, *guardrailProfileSet) {
	t.Helper()
	dir := t.TempDir()
	raw := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: " +
		filepath.Join(guardrailPoliciesRoot(t), "default") + "\n  default_profile: eng\n  profile_assignments:\n"
	if withAct {
		raw += "  - match:\n      groups:\n      - dc-r102-nested\n    profile: j04-act\n"
	}
	raw += "  - match:\n      groups:\n      - dc-r102-devs\n    profile: eng\n  profiles:\n    eng:\n      description: eng\n"
	if withAct {
		raw += "    j04-act:\n      mode: action\n"
	}
	raw += "observability: {}\n"
	path := filepath.Join(dir, config.DefaultConfigName)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	cache := guardrail.NewRulePackCache()
	global, err := loadGlobalRulePack(cache, cfg, "global")
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := newGuardrailProfileSet(cfg, cache, true)
	if err != nil {
		t.Fatal(err)
	}
	g, err := buildGeneration(t.Context(), generationInputs{cfg: cfg, raw: []byte(raw),
		rulePacks: &sidecarRulePackCandidate{global: global, active: global}, profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	g.N = n
	return g, profiles
}

// gap0487Fixture is /llm in front of the guardrail proxy a Substrate gateway
// keeps for actors when its own guardrail proxy is off (guardrail.enabled
// unset, the chart default): Sidecar.substrateLLMProxy. The sidecar's
// published generation holds j04-act (added to the ConfigMap after start);
// the process-wide profile set the API server published at boot does not.
// The actor eng2 is in dc-r102-nested and runs Claude Code.
func gap0487Fixture(t *testing.T) (*substrateFixture, *gap0487Upstream, string) {
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
	providerDomains = append(providerDomains, struct {
		domain string
		name   string
	}{host, "bedrock"})
	t.Cleanup(func() { providerDomains = orig })

	boot, bootProfiles := gap0487Gen(t, false, 1)
	live, _ := gap0487Gen(t, true, 2)
	store, logger := testStoreAndV8Logger(t)
	s := &Sidecar{cfg: boot.Config, health: NewSidecarHealth(), store: store, logger: logger}
	s.cfgCurrent.Store(live.Config)
	s.generation.Store(live)
	if s.proxySnapshot() != nil {
		t.Fatal("the sidecar runs its own guardrail proxy; this fixture is the one without")
	}
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
		"tok-eng2": {Atespace: "dc-j04", Name: "j04-1", UID: uid, Subject: "actor/dc-j04/j04-1"},
	}}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.LLM = llm; c.Actors = tokens })
	f.api.SetGenerationSource(s.Generation)
	f.api.setGuardrailProfiles(bootProfiles)
	person := registry.Person{Kind: "human", Issuer: "https://idp.example", Subject: "eng2", Principal: "eng2@example.com", Groups: []string{"dc-r102-nested"}}
	if err := f.regs.Put(context.Background(), registry.Registration{Atespace: "dc-j04", Name: "j04-1", UID: uid,
		Connector: "claudecode", Profile: "j04-act", Person: person}); err != nil {
		t.Fatal(err)
	}
	f.live["dc-j04/j04-1"] = identity.LiveActor{UID: uid, State: identity.ActorRunning}
	return f, up, store.DatabasePath()
}

// GAP-0487: the guardrail proxy a Substrate gateway keeps for actors was
// built without the sidecar's wiring (setGuardrailProxy): no generation
// source, so an actor's /llm request resolved its guardrail profile from the
// process-wide set, not from the configuration generation in force that the
// hook path pins. With the action-mode profile only in the generation, the
// AWS key canary (user, system, tool result, an earlier turn) was found
// CRITICAL and still reached Bedrock in alert mode, while the hook refused
// the same key.
func TestGAP0487LLMRequestCanaryIsRefusedInActionMode(t *testing.T) {
	f, up, db := gap0487Fixture(t)
	invoke := "/llm/bedrock/model/us.anthropic.claude-haiku-5-5/invoke"
	const head = `{"anthropic_version":"bedrock-2023-05-31","max_tokens":20,`
	// The control reaches the model.
	rec := f.do(t, f.actor, http.MethodPost, invoke, "tok-eng2", head+`"messages":[{"role":"user","content":"Say OK"}]}`)
	if got := up.take(); rec.Code != http.StatusOK || len(got) != 1 {
		t.Fatalf("control: %d upstream=%d %s", rec.Code, len(got), rec.Body)
	}
	for name, body := range map[string]string{
		"user":    head + `"messages":[{"role":"user","content":"remember ` + gap0487Canary + `"}]}`,
		"system":  head + `"system":"note ` + gap0487Canary + `","messages":[{"role":"user","content":"Say OK"}]}`,
		"toolres": head + `"messages":[{"role":"user","content":"run it"},{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"bash","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"out ` + gap0487Canary + `"}]}]}`,
		"earlier": head + `"messages":[{"role":"user","content":"` + gap0487Canary + `"},{"role":"assistant","content":"ok"},{"role":"user","content":"hello"}]}`,
	} {
		rec := f.do(t, f.actor, http.MethodPost, invoke, "tok-eng2", body)
		got := up.take()
		t.Logf("%s: code=%d upstream=%d body=%.200s", name, rec.Code, len(got), rec.Body.String())
		for _, b := range got {
			if strings.Contains(b, gap0487Canary) {
				t.Errorf("%s: the canary reached Bedrock (%d)", name, rec.Code)
			}
		}
	}
	if rows := gap0487FindingRows(t, db); len(rows) == 0 {
		t.Errorf("no audit row records the SEC-AWS-KEY finding")
	}
}

// GAP-0487 reply side: a streamed model reply naming the credentials file
// and carrying the key, on invoke-with-response-stream.
func TestGAP0487LLMStreamedReplyCanaryIsInspected(t *testing.T) {
	f, up, db := gap0487Fixture(t)
	up.mu.Lock()
	up.reply = bedrockInvokeStreamFrames(t, "cat ~/.aws/credentials gives ", gap0487Canary, " as the key")
	up.ctype = "application/vnd.amazon.eventstream"
	up.mu.Unlock()
	rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/model/us.anthropic.claude-haiku-5-5/invoke-with-response-stream", "tok-eng2",
		`{"anthropic_version":"bedrock-2023-05-31","max_tokens":20,"messages":[{"role":"user","content":"Where are my keys?"}]}`)
	t.Logf("stream reply: code=%d upstream=%d body=%.300q", rec.Code, len(up.take()), rec.Body.String())
	if text := gap0487StreamText(rec.Body.String()); strings.Contains(text, gap0487Canary) || !strings.Contains(text, "defenseclaw_blocked") {
		t.Errorf("the streamed reply was not blocked: %.300s", text)
	}
	if rows := gap0487FindingRows(t, db); len(rows) == 0 {
		t.Errorf("no audit row records the SEC-AWS-KEY finding of the reply")
	}
}

// gap0487FindingRows lists "event_name/action" of every audit row that names
// the AWS key rule.
func gap0487FindingRows(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT event_name, COALESCE(action, '') FROM audit_events WHERE projected_record_json LIKE '%SEC-AWS-KEY%' ORDER BY rowid`)
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

// gap0487StreamText is the decoded payloads of a Bedrock event stream body.
func gap0487StreamText(body string) string {
	var out strings.Builder
	for _, m := range regexp.MustCompile(`"bytes":"([A-Za-z0-9+/=]+)"`).FindAllStringSubmatch(body, -1) {
		if b, err := base64.StdEncoding.DecodeString(m[1]); err == nil {
			out.Write(b)
		}
	}
	return out.String()
}
