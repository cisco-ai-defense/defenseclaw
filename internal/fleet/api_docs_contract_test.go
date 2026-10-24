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
	"strconv"
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

// commonStatusCodes returns the codes in the page's "Common status codes" table.
func commonStatusCodes(t *testing.T) map[int]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "reference", "edge-connector", "api.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(raw), "## Common status codes")
	if !ok {
		t.Fatal("api.mdx has no Common status codes section")
	}
	codes := map[int]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([0-9]{3})` \\|").FindAllStringSubmatch(table, -1) {
		code, _ := strconv.Atoi(m[1])
		codes[code] = true
	}
	return codes
}

// GAP-0569: every status the fleet handlers write, and the 405 its router
// returns, is in the common table.
func TestCommonStatusCodesListEveryFleetStatus(t *testing.T) {
	names := map[string]int{}
	for code := 100; code < 600; code++ {
		if text := http.StatusText(code); text != "" {
			names["Status"+strings.NewReplacer(" ", "", "-", "").Replace(text)] = code
		}
	}
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	documented := commonStatusCodes(t)
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`http\.(Status[A-Za-z]+)\b`).FindAllStringSubmatch(string(src), -1) {
		code, ok := names[m[1]]
		if !ok {
			t.Fatalf("cannot resolve http.%s", m[1])
		}
		if !documented[code] && !seen[m[1]] {
			t.Errorf("api.go writes %d (http.%s); the Common status codes table omits it", code, m[1])
		}
		seen[m[1]] = true
	}

	recorder := httptest.NewRecorder()
	setupAPIWithPolicyT(t).Handler().ServeHTTP(recorder, authedRequest(http.MethodPut, "/devices", nil))
	if recorder.Code != http.StatusMethodNotAllowed || strings.TrimSpace(recorder.Body.String()) != "Method Not Allowed" {
		t.Fatalf("PUT /devices: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if !documented[http.StatusMethodNotAllowed] {
		t.Error("the router returns 405; the Common status codes table omits it")
	}
}
