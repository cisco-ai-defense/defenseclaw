// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func usageRecord(subject string, groups []string, usd float64) modelusage.Record {
	cost := usd
	return modelusage.Record{
		Facts: modelusage.CallFacts{
			Connector: "claudecode", SelectedProvider: "anthropic", SelectedModel: "m", CallRole: modelusage.RoleAgent,
			APIFamily: modelusage.FamilyMessages, Subject: subject, SubjectKind: useridentity.KindPOSIXUID,
			IdentityVerified: subject != "", Groups: groups,
		},
		Usage:   modelusage.Usage{Input: 10, Output: 5, Has: modelusage.HasInput | modelusage.HasOutput},
		Cost:    modelusage.Cost{USD: &cost, Basis: modelusage.BasisComputed},
		Outcome: "completed", EndedAt: time.Now(), Total: time.Millisecond,
	}
}

func usageAPI(t *testing.T, standalone bool) (*APIServer, *modelusage.Store) {
	t.Helper()
	cfg := &config.Config{}
	if standalone {
		cfg = &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	}
	api := &APIServer{configSnapshot: func() *config.Config { return cfg }}
	store := modelusage.NewStore(filepath.Join(t.TempDir(), "model_usage.db"))
	if err := store.Configure(true, 30); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Configure(false, 30) })
	api.SetModelUsageQuerier(store)
	store.Emit(context.Background(), usageRecord("1001", []string{"eng"}, 0.5))
	store.Emit(context.Background(), usageRecord("1002", []string{"ops"}, 2))
	return api, store
}

func getUsage(t *testing.T, api *APIServer, ctx context.Context, query string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/usage?"+query, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	api.handleUsage(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestUsageEndpointOffReportsDisabled(t *testing.T) {
	api := &APIServer{configSnapshot: func() *config.Config { return &config.Config{} }}
	code, body := getUsage(t, api, context.Background(), "")
	if code != http.StatusOK || body["enabled"] != false {
		t.Fatalf("%d %v", code, body)
	}
	api.SetModelUsageQuerier(modelusage.NewStore(filepath.Join(t.TempDir(), "x.db"))) // bound but closed
	if _, body = getUsage(t, api, context.Background(), ""); body["enabled"] != false {
		t.Fatalf("%v", body)
	}
}

func TestUsageEndpointPerUserGatewaySeesItsRows(t *testing.T) {
	api, _ := usageAPI(t, false)
	code, body := getUsage(t, api, context.Background(), "by=model&since=7d")
	if code != http.StatusOK || body["scope"] != "all" {
		t.Fatalf("%d %v", code, body)
	}
}

func TestUsageEndpointManagedUserSeesOnlyOwnRows(t *testing.T) {
	api, _ := usageAPI(t, true)
	alice := context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, "1001")
	code, body := getUsage(t, api, alice, "by=model")
	rows, _ := body["rows"].([]any)
	if code != http.StatusOK || body["scope"] != "own" || len(rows) != 1 {
		t.Fatalf("%d %v", code, body)
	}
	row := rows[0].(map[string]any)
	if row["calls"].(float64) != 1 || row["cost_usd"].(float64) != 0.5 {
		t.Fatalf("a user must see only their own call: %v", row)
	}
	// the per-group rollup is admin-only
	if code, _ = getUsage(t, api, alice, "by=group"); code != http.StatusForbidden {
		t.Fatalf("group rollup for a user = %d", code)
	}
	// a caller the gateway could not verify sees nothing
	if code, _ = getUsage(t, api, context.Background(), "by=model"); code != http.StatusForbidden {
		t.Fatalf("unverified caller = %d", code)
	}
	if code, _ = getUsage(t, api, alice, "by=nonsense"); code != http.StatusBadRequest {
		t.Fatalf("unknown rollup = %d", code)
	}
	if code, _ = getUsage(t, api, alice, "since=banana"); code != http.StatusBadRequest {
		t.Fatalf("bad since = %d", code)
	}
}

func TestUsageEndpointRejectsNonGet(t *testing.T) {
	api, _ := usageAPI(t, false)
	rec := httptest.NewRecorder()
	api.handleUsage(rec, httptest.NewRequest(http.MethodPost, "/usage", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal(rec.Code)
	}
}

func TestOwnUsageSummaryIsTheCallerOwnRowsOnly(t *testing.T) {
	api, _ := usageAPI(t, true)
	got := api.ownUsageSummary(context.Background(), "uid", "1001")
	if got == nil || got["calls"].(int64) != 1 || got["cost_usd"].(float64) != 0.5 {
		t.Fatalf("%v", got)
	}
	if api.ownUsageSummary(context.Background(), "uid", "4242") != nil {
		t.Fatal("an account with no usage gets no usage block")
	}
	if (&APIServer{}).ownUsageSummary(context.Background(), "uid", "1001") != nil {
		t.Fatal("no store, no usage block")
	}
}
