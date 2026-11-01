// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// GAP-0526: a managed Windows scan of a folder in a user profile told the
// caller to scan it as the signed-in user, which managed scans refuse a
// standard account. The refusal names the administrator's copy and scan.
func TestWindowsProfileScanRefusalNamesTheAdministratorsCopyAndScan(t *testing.T) {
	restore := requireGatewayPathOutsideUserProfiles
	t.Cleanup(func() { requireGatewayPathOutsideUserProfiles = restore })
	requireGatewayPathOutsideUserProfiles = func(string) error {
		return errors.New("the managed gateway runs as LocalSystem and does not read inside user profiles")
	}
	t.Setenv("ProgramFiles", `C:\Program Files`)
	target := `C:\Users\dcw-std1\r102-wave\wm5\bad-skill`
	body, _ := json.Marshal(map[string]string{"target": target})
	rec := httptest.NewRecorder()
	(&APIServer{}).handleSkillScan(rec, httptest.NewRequest(http.MethodPost, "/v1/skill/scan", strings.NewReader(string(body))))
	var answer map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil || rec.Code != http.StatusForbidden {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	message := answer["error"]
	for _, want := range []string{
		"standard accounts cannot run managed scans",
		"Copy-Item -Recurse -Force -LiteralPath '" + target + `' -Destination 'C:\DefenseClawReview\bad-skill'`,
		`& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe' scan skill 'C:\DefenseClawReview\bad-skill'`,
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("refusal lacks %q: %s", want, message)
		}
	}
	if strings.Contains(message, "signed-in user") {
		t.Fatalf("refusal still names a scan the standard account cannot run: %s", message)
	}
	// A name with a quote stays one PowerShell string.
	if step := windowsProfileScanNextStep("plugin", `C:\Users\o'neil\p\`); !strings.Contains(step, `-LiteralPath 'C:\Users\o''neil\p\' -Destination 'C:\DefenseClawReview\p'`) {
		t.Fatalf("quoted step = %s", step)
	}
}
