// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/policy"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Empty and populated responses keep the same array shape with either store.
func TestPolicyVersionsResponseIsAnArrayForEveryStore(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			api := setupAPIWithPolicyT(t)
			store := api.policy.Store()
			if backend == "sqlite" {
				dir := filepath.Join(t.TempDir(), "fleet")
				if err := safefile.ProtectDirectory(dir); err != nil {
					t.Fatal(err)
				}
				sqlite, err := policy.NewSQLitePolicyStore(filepath.Join(dir, "policy.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sqlite.Close() })
				store = sqlite
				api.policy = policy.NewService(store, nil, nil, nil)
			}
			for _, count := range []int{0, 1} {
				if count == 1 {
					if err := store.SavePolicy(1, 2, 1, []byte{1}, nil, "standard"); err != nil {
						t.Fatal(err)
					}
				}
				recorder := httptest.NewRecorder()
				api.Handler().ServeHTTP(recorder, authedRequest(http.MethodGet, "/policy/versions?tenant_id=1&fleet_id=2", nil))
				var response struct {
					Versions json.RawMessage `json:"versions"`
				}
				if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil {
					t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
				}
				var versions []policy.PolicyRecord
				if len(response.Versions) == 0 || response.Versions[0] != '[' || json.Unmarshal(response.Versions, &versions) != nil || len(versions) != count {
					t.Fatalf("versions=%s, want an array with %d entries", response.Versions, count)
				}
			}
		})
	}
}

// Check all composite IDs in the examples, including URLs and batch results.
func TestDocumentedDeviceCompositeIDs(t *testing.T) {
	path := filepath.Join("..", "..", "docs-site", "content", "docs", "reference", "edge-connector", "api.mdx")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, id := range regexp.MustCompile(`281[0-9]{12}`).FindAllString(text, -1) {
		found := false
		for _, device := range []uint32{1001, 1002, 9999} {
			if id == fmtCompositeID(1, 2, device) {
				found = true
			}
		}
		if !found {
			t.Errorf("documented composite ID %s does not match tenant 1, fleet 2 and an example device", id)
		}
	}
	if !strings.Contains(text, fmtCompositeID(1, 2, 1001)) {
		t.Fatal("the registration response does not contain the registered device's composite ID")
	}
}

func fmtCompositeID(tenant, fleet uint16, device uint32) string {
	encoded, _ := json.Marshal(manager.ComposeID(tenant, fleet, device))
	return string(encoded)
}
