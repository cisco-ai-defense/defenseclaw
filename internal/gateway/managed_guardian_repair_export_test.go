// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestManagedGuardianRepairAuditExportsRepairedAccount(t *testing.T) {
	fixture, api, _ := newCLIObservabilityV8Fixture(t)
	handler := api.managedHookPeerAuth(newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil), api.managedHookSocketMux())
	request := httptest.NewRequest(http.MethodPost, managedGuardianRepairAuditPath,
		strings.NewReader(`{"user":"alice","uid":4242,"connector":"copilot"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "hook-guardian")
	request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{UID: 0}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("root repair report status=%d: %s", response.Code, response.Body.String())
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := fixture.store.ExportJSONL(path, 100, audit.ExportJSONLOptions{}); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var repairs []audit.Event
	for scanner.Scan() {
		var event audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Action == string(audit.ActionConnectorHookRepaired) {
			repairs = append(repairs, event)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(repairs) != 1 || repairs[0].Connector != "copilot" ||
		repairs[0].Structured[auditUserIDKey] != "4242" ||
		repairs[0].Structured[auditUserIDKindKey] != "posix_uid" ||
		repairs[0].Structured[auditUserNameKey] != "alice" {
		t.Fatalf("exported repair attribution = %+v", repairs)
	}
}
