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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

	*recorded = nil
	code, _ = enforceRequest(t, api.handleEnforceBlock, http.MethodDelete, `{"target_type":"skill","target_name":"s1"}`)
	if code != http.StatusOK || !reflect.DeepEqual(*recorded, []configwrite.Change{{Path: "asset_policy.skill.denied", Value: []map[string]any{}}}) {
		t.Fatalf("unblock = %d %#v", code, *recorded)
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
