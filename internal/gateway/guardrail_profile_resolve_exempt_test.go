// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A no-profile deployment still has an organization sandbox floor. Resolve
// must report the same enrollment exemption as the hook for that floor.
func TestProfileResolveWithoutProfilesReportsHookExemption(t *testing.T) {
	previousLookup, previousFacts := profileExplainSubjectLookup, managedHookExemptFacts
	previousEnabled := identityFactsEnabled.Load()
	t.Cleanup(func() {
		profileExplainSubjectLookup, managedHookExemptFacts = previousLookup, previousFacts
		setIdentityFactsEnabled(previousEnabled)
		liveGuardrailProfiles.Store(nil)
	})
	liveGuardrailProfiles.Store(nil)
	setIdentityFactsEnabled(true)
	facts := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
		Source: useridentity.SourceSSSD, Assurance: useridentity.AssuranceVerified,
		AccountDomain: "CORP", Domain: "corp.example", Principal: "carol@corp.example", ResolvedAt: time.Now()}
	managedHookExemptFacts = func(uid int, _ bool) (useridentity.DirectoryFacts, exemptFactsState) {
		if uid == 2203 {
			return facts, exemptFactsCurrent
		}
		return facts, exemptFactsNone
	}
	profileExplainSubjectLookup = func(name string) (profileSubject, error) {
		switch name {
		case "alice":
			return profileSubject{UserID: "2201", IDKind: useridentity.KindPOSIXUID, UserName: "alice"}, nil
		case "bob":
			return profileSubject{UserID: "2202", IDKind: useridentity.KindPOSIXUID, UserName: "bob"}, nil
		case "root":
			return profileSubject{UserID: "0", IDKind: useridentity.KindPOSIXUID, UserName: "root"}, nil
		case "carol":
			return profileSubjectFromVerified(VerifiedSubject{UserID: "2203", IDKind: useridentity.KindPOSIXUID,
				UserName: "carol@corp.example", Directory: facts}, false), nil
		}
		t.Fatalf("unexpected subject %q", name)
		return profileSubject{}, nil
	}
	cfg := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.OpenShell.Admin.RequiredFor = []string{"claudecode"}
	cfg.Enterprise.Enrollment.ExemptUsers = []string{"alice", "root", `CORP\carol`}
	api := newAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	if api.guardrailProfileSet() != nil || !cfg.StandaloneEnterprise() {
		t.Fatal("fixture must be standalone with no guardrail profiles")
	}
	resolve := func(name string) (map[string]json.RawMessage, []byte) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user="+url.QueryEscape(name), nil)
		req.RemoteAddr = "127.0.0.1:40000"
		req = req.WithContext(withServiceAccountGateway(req.Context()))
		rec := httptest.NewRecorder()
		api.handleGuardrailProfileResolve(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d: %s", name, rec.Code, rec.Body.String())
		}
		var answer map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
			t.Fatalf("%s: %v: %s", name, err, rec.Body.String())
		}
		return answer, rec.Body.Bytes()
	}
	for _, tc := range []struct {
		peer   managedHookPeer
		exempt bool
	}{
		{managedHookPeer{UID: 2201, Name: "alice"}, true},
		{managedHookPeer{UID: 2202, Name: "bob"}, false},
		{managedHookPeer{UID: 0, Name: "root"}, false},
		// Only verified directory facts can match this entry. A CLI-side
		// uid/account-name comparison cannot discover it.
		{managedHookPeer{UID: 2203, Name: "carol@corp.example"}, true},
	} {
		name := tc.peer.Name
		if tc.peer.UID == 2203 {
			name = "carol"
		}
		t.Run(name, func(t *testing.T) {
			answer, body := resolve(name)
			if string(answer["profiles_configured"]) != "false" || string(answer["profile"]) != `""` ||
				string(answer["match"]) != `""` || len(answer["effective"]) == 0 || len(answer["subject"]) == 0 {
				t.Fatalf("incomplete no-profile answer: %s", body)
			}
			_, hasEnrollment := answer["enrollment"]
			if hasEnrollment != tc.exempt {
				t.Fatalf("enrollment present=%t, want %t: %s", hasEnrollment, tc.exempt, body)
			}
			if tc.exempt {
				var enrollment struct {
					Exempt bool `json:"exempt"`
				}
				if err := json.Unmarshal(answer["enrollment"], &enrollment); err != nil || !enrollment.Exempt {
					t.Fatalf("enrollment = %s (%v)", answer["enrollment"], err)
				}
				var warnings []string
				if err := json.Unmarshal(answer["warnings"], &warnings); err != nil || len(warnings) != 1 ||
					!strings.Contains(warnings[0], "required_for never refuses its host runs") ||
					!strings.Contains(warnings[0], "still inspected under the guardrail settings and logged") ||
					!strings.Contains(warnings[0], "defenseclaw.user.enrollment: exempt") ||
					strings.Contains(warnings[0], "profile above") || strings.Contains(warnings[0], "block_at") {
					t.Fatalf("warnings = %s (%v)", answer["warnings"], err)
				}
			}
			decision := (&managedHookAuthorizer{enrollment: cfg.Enterprise.Enrollment}).decide(tc.peer, "claudecode", "")
			if decision.Exempt != tc.exempt || decision.Exempt != hasEnrollment {
				t.Fatalf("hook exempt=%t, resolve enrollment present=%t, want=%t", decision.Exempt, hasEnrollment, tc.exempt)
			}
			ctx := attachVerifiedSubject(withManagedHookPeer(context.Background(), tc.peer), nil,
				strconv.Itoa(tc.peer.UID), tc.peer.Name, subjectSourcePeerCredentials)
			if decision.Exempt {
				ctx = withEnterpriseExemptUser(ctx)
			}
			outcome := api.requireSandboxDecision(ctx, "claudecode", "UserPromptSubmit", "/p", "")
			if (outcome.Outcome == requireSandboxExempt) != tc.exempt {
				t.Fatalf("hook gate outcome %q, exempt=%t: %s", outcome.Outcome, tc.exempt, body)
			}
			if name == "alice" {
				t.Logf("no-profile-exempt-response: %s", body)
			}
		})
	}
	// A failed directory lookup is reported, and the uid/account-name
	// exemption the hook applies still shows, as it does with profiles.
	lookup := profileExplainSubjectLookup
	profileExplainSubjectLookup = func(string) (profileSubject, error) {
		return profileSubject{UserID: "2201", IDKind: useridentity.KindPOSIXUID, UserName: "alice"}, errors.New("directory unavailable")
	}
	failed, body := resolve("alice")
	var failedEnrollment struct {
		Exempt bool `json:"exempt"`
	}
	if err := json.Unmarshal(failed["enrollment"], &failedEnrollment); err != nil || !failedEnrollment.Exempt ||
		string(failed["lookup_error"]) != `"directory unavailable"` {
		t.Fatalf("lookup-error answer: %s", body)
	}
	profileExplainSubjectLookup = lookup
	// The exemption warning and the existing inert-HILT warning coexist.
	cfg.Guardrail.HILT = config.HILTConfig{Enabled: true, MinSeverity: "HIGH"}
	cfg.Guardrail.BlockAt = "MEDIUM"
	answer, body := resolve("alice")
	var warnings []string
	if err := json.Unmarshal(answer["warnings"], &warnings); err != nil || len(warnings) != 2 ||
		!strings.Contains(warnings[0], "exempt_users") || !strings.Contains(warnings[1], "human approval") {
		t.Fatalf("combined warnings = %s (%v): %s", answer["warnings"], err, body)
	}
}
