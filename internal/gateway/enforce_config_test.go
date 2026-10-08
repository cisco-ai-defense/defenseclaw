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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"gopkg.in/yaml.v3"
)

// enforceTestAPI is an APIServer over a temp config.yaml holding body, with
// a recording writer in place of configwrite.Apply.
func enforceTestAPI(t *testing.T, body string) (*APIServer, *[]configwrite.Change) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	store, logger := testStoreAndLogger(t)
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, &config.Config{ConfigFilePath: path})
	var recorded []configwrite.Change
	api.configApply = func(_ context.Context, gotPath string, changes []configwrite.Change, opt configwrite.Options) (configwrite.Result, error) {
		if gotPath != path || opt.ExpectSHA256 == "" || opt.Actor == "" {
			t.Errorf("writer call path=%q expect=%q actor=%q", gotPath, opt.ExpectSHA256, opt.Actor)
		}
		recorded = append(recorded, changes...)
		return configwrite.Result{Generation: 7}, nil
	}
	return api, &recorded
}

func enforceRequest(t *testing.T, handler http.HandlerFunc, method, body string) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(method, "/enforce/block", bytes.NewReader([]byte(body))))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// TestEnforceBlockWritesAssetPolicy: /enforce/block changes config.yaml
// asset_policy through the writer (replacing an allow for the same asset),
// and DELETE removes only the deny.
func TestEnforceBlockWritesAssetPolicy(t *testing.T) {
	api, recorded := enforceTestAPI(t, "asset_policy:\n  skill:\n    allowed:\n      - {name: s1, reason: vetted}\n      - {name: other}\n")
	api.SetGenerationSource(func() *Generation { return &Generation{Digest: "sha256:applied"} })

	code, out := enforceRequest(t, api.handleEnforceBlock, http.MethodPost, `{"target_type":"skill","target_name":"s1","reason":"bad"}`)
	if code != http.StatusOK || out["status"] != "blocked" || out["generation"] != float64(7) ||
		out["effective_policy_digest"] != "sha256:applied" {
		t.Fatalf("block = %d %v", code, out)
	}
	want := []configwrite.Change{
		{Path: "asset_policy.skill.denied", Value: []map[string]any{{"name": "s1", "reason": "bad"}}},
		{Path: "asset_policy.skill.allowed", Value: []map[string]any{{"name": "other"}}},
	}
	if !reflect.DeepEqual(*recorded, want) {
		t.Fatalf("changes = %#v", *recorded)
	}

	api.scannerCfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "s1", Connector: "codex", Reason: "vetted"}}
	w := httptest.NewRecorder()
	api.handleEnforceAllowed(w, httptest.NewRequest(http.MethodGet, "/enforce/allowed", nil))
	var listed []enforcementEntry
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed) != 1 ||
		listed[0].ID != "asset_policy:skill:s1@codex" || listed[0].Connector != "codex" {
		t.Fatalf("GET /enforce/allowed = %v %s", err, w.Body.String())
	}

	// Skill names match case-insensitively, so an unblock in another case
	// removes the rule that still blocked it (GAP-0319).
	cased, casedRecorded := enforceTestAPI(t, "asset_policy:\n  skill:\n    denied:\n      - {name: MySkill}\n")
	if code, out := enforceRequest(t, cased.handleEnforceBlock, http.MethodDelete, `{"target_type":"skill","target_name":"myskill"}`); code != http.StatusOK ||
		!reflect.DeepEqual(*casedRecorded, []configwrite.Change{{Path: "asset_policy.skill.denied", Value: []map[string]any{}}}) {
		t.Fatalf("unblock in another case = %d %v %#v", code, out, *casedRecorded)
	}

	*recorded = nil
	// A reload the gateway refused is reported, not the old digest.
	api.configReloader = func(context.Context, string) error { return errors.New("requires gateway restart for: data_dir") }
	code, out = enforceRequest(t, api.handleEnforceBlock, http.MethodDelete, `{"target_type":"skill","target_name":"s1"}`)
	if code != http.StatusOK || !reflect.DeepEqual(*recorded, []configwrite.Change{{Path: "asset_policy.skill.denied", Value: []map[string]any{}}}) ||
		out["applied"] != false || out["effective_policy_digest"] != nil {
		t.Fatalf("unblock = %d %v %#v", code, out, *recorded)
	}
}

// A watcher block belongs to the connector that owns the scanned copy.
func TestEnforceUnblockClearsConnectorWatcherBlock(t *testing.T) {
	api, _ := enforceTestAPI(t, "asset_policy:\n  skill:\n    denied:\n      - {name: shared-skill, connector: codex}\n")
	for _, connector := range []string{"", "codex", "claudecode"} {
		if err := api.store.SetActionFieldForConnector("skill", "shared-skill", connector, "install", "block", "watcher"); err != nil {
			t.Fatal(err)
		}
	}
	if err := api.store.SetActionFieldForConnector("skill", "shared-skill", "codex", "runtime", "disable", "watcher"); err != nil {
		t.Fatal(err)
	}

	code, out := enforceRequest(t, api.handleEnforceBlock, http.MethodDelete,
		`{"target_type":"skill","target_name":"shared-skill","connector":"codex"}`)
	if code != http.StatusOK || out["status"] != "unblocked" {
		t.Fatalf("unblock = %d %v", code, out)
	}
	codex, err := api.store.GetActionForConnector("skill", "shared-skill", "codex")
	if err != nil || codex == nil || codex.Actions.Install != "" || codex.Actions.Runtime != "disable" {
		t.Fatalf("codex journal = %+v, %v; want install cleared and runtime retained", codex, err)
	}
	global, err := api.store.GetAction("skill", "shared-skill")
	if err != nil || global != nil && global.Actions.Install != "" {
		t.Fatalf("older global journal = %+v, %v; want install cleared", global, err)
	}
	claude, err := api.store.GetActionForConnector("skill", "shared-skill", "claudecode")
	if err != nil || claude == nil || claude.Actions.Install != "block" {
		t.Fatalf("other connector journal = %+v, %v; want install block retained", claude, err)
	}
}

func TestEnforceAllowWriterFailureDoesNotEnableRuntime(t *testing.T) {
	received := make(chan receivedRequest, 1)
	srv := startMockGW(t, rpcRecordingLoop(received))
	api, _ := enforceTestAPI(t, "{}\n")
	api.client = connectToMockGW(t, srv)
	api.configApply = func(context.Context, string, []configwrite.Change, configwrite.Options) (configwrite.Result, error) {
		return configwrite.Result{}, errors.New("writer rejected edit")
	}
	pe := enforce.NewPolicyEngine(api.store)
	if err := pe.Disable("skill", "blocked-skill", "runtime blocked"); err != nil {
		t.Fatal(err)
	}

	code, _ := enforceRequest(t, api.handleEnforceAllow, http.MethodPost, `{"target_type":"skill","target_name":"blocked-skill"}`)
	if code != http.StatusInternalServerError {
		t.Fatalf("allow status = %d, want 500", code)
	}
	select {
	case rpc := <-received:
		t.Fatalf("runtime enabled before config edit: %s", rpc.Method)
	default:
	}
	disabled, err := api.store.HasAction("skill", "blocked-skill", "runtime", "disable")
	if err != nil || !disabled {
		t.Fatalf("runtime journal disabled = %t, %v; want true", disabled, err)
	}
}

// TestEnforceRefusedOnManagedStandalone: a managed standalone device refuses
// local policy writes; the admin config is the truth.
func TestEnforceRefusedOnManagedStandalone(t *testing.T) {
	api, recorded := enforceTestAPI(t, "{}\n")
	api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone

	code, out := enforceRequest(t, api.handleEnforceAllow, http.MethodPost, `{"target_type":"mcp","target_name":"m1"}`)
	if code != http.StatusForbidden || out["error"] != "managed_device" || len(*recorded) != 0 {
		t.Fatalf("managed allow = %d %v, writes %d", code, out, len(*recorded))
	}
	// The refused attempt is in the audit trail.
	events, err := api.store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == "api-enforce-allow" && strings.Contains(event.Details, "outcome=refused reason=managed_device") {
			return
		}
	}
	t.Fatalf("no refused api-enforce-allow audit event in %d events", len(events))
}

// A URL-only rule is listed under its URL and must be removable by that key.
func TestEnforceUnblockListedURLRule(t *testing.T) {
	url := "https://example.invalid/mcp"
	api, recorded := enforceTestAPI(t, "asset_policy:\n  mcp:\n    denied:\n      - {url: https://example.invalid/mcp, reason: blocked}\n")
	api.scannerCfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: url, Reason: "blocked"}}

	w := httptest.NewRecorder()
	api.handleEnforceBlocked(w, httptest.NewRequest(http.MethodGet, "/enforce/blocked", nil))
	var entries []enforcementEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil || len(entries) != 1 {
		t.Fatalf("listed rules = %v %s", err, w.Body.String())
	}
	code, out := enforceRequest(t, api.handleEnforceBlock, http.MethodDelete,
		`{"target_type":"mcp","target_name":"`+entries[0].TargetName+`"}`)
	want := []configwrite.Change{{Path: "asset_policy.mcp.denied", Value: []map[string]any{}}}
	if code != http.StatusOK || !reflect.DeepEqual(*recorded, want) {
		t.Fatalf("unblock = %d %v, changes %#v; want %#v", code, out, *recorded, want)
	}
}

// A listed URL is a selector, not the MCP server name.
func TestEnforceBlockListedMCPURLKeepsSelector(t *testing.T) {
	url := "https://example.invalid/mcp"
	api, recorded := enforceTestAPI(t, "asset_policy:\n  mcp:\n    allowed:\n      - {url: https://example.invalid/mcp}\n")
	api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{URL: url}}
	w := httptest.NewRecorder()
	api.handleEnforceAllowed(w, httptest.NewRequest(http.MethodGet, "/enforce/allowed", nil))
	var entries []enforcementEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil || len(entries) != 1 {
		t.Fatalf("listed rules = %v %s", err, w.Body.String())
	}
	code, out := enforceRequest(t, api.handleEnforceBlock, http.MethodPost,
		`{"target_type":"mcp","target_name":"`+entries[0].TargetName+`"}`)
	if code != http.StatusOK || out["status"] != "blocked" {
		t.Fatalf("block = %d %v", code, out)
	}
	raw, err := yaml.Marshal((*recorded)[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	var rules []config.AssetPolicyRule
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.MCP.Denied = rules
	verdict, _ := cfg.AssetListDecision(config.AssetPolicyInput{TargetType: "mcp", Name: "notes", URL: url})
	if verdict != config.AssetListDeny || len(rules) != 1 || rules[0].Name != "" || rules[0].URL != url {
		t.Fatalf("denied=%+v verdict=%q, want URL-only deny", rules, verdict)
	}
}

// A listed deny URL must become an allow for that URL, independent of name.
func TestEnforceAllowListedMCPURLKeepsSelector(t *testing.T) {
	url := "https://example.invalid/mcp"
	api, recorded := enforceTestAPI(t, "asset_policy:\n  mcp:\n    denied:\n      - {url: https://example.invalid/mcp}\n")
	api.scannerCfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: url}}
	w := httptest.NewRecorder()
	api.handleEnforceBlocked(w, httptest.NewRequest(http.MethodGet, "/enforce/blocked", nil))
	var entries []enforcementEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil || len(entries) != 1 {
		t.Fatalf("listed rules = %v %s", err, w.Body.String())
	}
	code, out := enforceRequest(t, api.handleEnforceAllow, http.MethodPost,
		`{"target_type":"mcp","target_name":"`+entries[0].TargetName+`"}`)
	if code != http.StatusOK || out["status"] != "allowed" {
		t.Fatalf("allow = %d %v", code, out)
	}
	raw, err := yaml.Marshal((*recorded)[1].Value)
	if err != nil {
		t.Fatal(err)
	}
	var rules []config.AssetPolicyRule
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.MCP.Default = "deny"
	cfg.AssetPolicy.MCP.Allowed = rules
	verdict, _ := cfg.AssetListDecision(config.AssetPolicyInput{TargetType: "mcp", Name: "notes", URL: url})
	if verdict != config.AssetListAllow || len(rules) != 1 || rules[0].Name != "" || rules[0].URL != url {
		t.Fatalf("allowed=%+v verdict=%q, want URL-only allow", rules, verdict)
	}
}
