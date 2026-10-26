// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// GAP-1711, GAP-1812, GAP-1813: a clean scan the session store could not
// apply (here: the account's removal lock cannot be taken) is a store race,
// not a finding. The gateway applies it again, each try a whole exchange,
// while the hook still waits (retry_until), and audits only the final
// answer: a call that ends up allowed leaves no HIGH block row, and one
// that stays unavailable leaves exactly one. A scan that found a hook, and
// an exchange of a hook that sends no retry_until, get the first answer.
func TestForeignHookSessionGatewayRetriesABusyCleanScanAndAuditsOnlyTheFinalAnswer(t *testing.T) {
	foreignHookGuardianDirForTest(t)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	identity := foreignHookTestIdentities(1)[0]
	previousLock, previousAudit := foreignHookAccountExchangeLock, foreignHookSessionDenialAudit
	t.Cleanup(func() { foreignHookAccountExchangeLock, foreignHookSessionDenialAudit = previousLock, previousAudit })
	var audited []string
	foreignHookSessionDenialAudit = func(_ *APIServer, _ context.Context, _ string, _ enterprisepolicy.SessionExchange, decision enterprisepolicy.GuardDecision) {
		audited = append(audited, decision.Reason)
	}
	request := func(deny, retry bool) *http.Request {
		decision := `{"deny":false}`
		if deny {
			decision = `{"deny":true,"reason":"enterprise_foreign_hook_blocked: project hook","findings":[{"path":"/repo/.claude/settings.json","digest":"aa11"}]}`
		}
		body := `{"key":{"connector":"claudecode","session":"s-1","process":"` + runtime.GOOS + `:b:4242:100"},"session_start":false,"decision":` + decision
		if retry {
			body += `,"retry_until":"` + time.Now().Add(3*time.Second).UTC().Format(time.RFC3339Nano) + `"`
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", strings.NewReader(body+"}"))
		ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
		ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
		return req.WithContext(ctx)
	}
	for _, tc := range []struct {
		name        string
		busy        int
		deny, retry bool
		wantDeny    string
		wantCalls   int
		wantAudited int
	}{
		{"busy once, then allowed", 1, false, true, "", 2, 0},
		{"busy twice, then allowed", 2, false, true, "", 3, 0},
		{"stays busy", 99, false, true, sessionRecordBusyText, 3, 1},
		{"hook sends no retry_until", 1, false, false, sessionRecordBusyText, 1, 1},
		{"scan found a hook", 1, true, true, sessionRecordBusyText, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audited = nil
			calls := 0
			foreignHookAccountExchangeLock = func(ctx context.Context, dataDir, identity string) (func(), error) {
				calls++
				if calls <= tc.busy {
					return nil, errors.New("lock unavailable")
				}
				return previousLock(ctx, dataDir, identity)
			}
			response := newDeadlineRecorder()
			api.handleForeignHookSession(response, request(tc.deny, tc.retry))
			body := response.Body.String()
			if response.Code != http.StatusOK {
				t.Fatalf("status %d: %s", response.Code, body)
			}
			if tc.wantDeny == "" && !strings.Contains(body, `"deny":false`) {
				t.Fatalf("a clean scan that the store applied on a retry must be allowed: %s", body)
			}
			if tc.wantDeny != "" && (!strings.Contains(body, `"deny":true`) || !strings.Contains(body, tc.wantDeny)) {
				t.Fatalf("want a denial with %q: %s", tc.wantDeny, body)
			}
			if calls != tc.wantCalls || len(audited) != tc.wantAudited {
				t.Fatalf("exchanges applied %d (want %d), denials audited %v (want %d)", calls, tc.wantCalls, audited, tc.wantAudited)
			}
		})
	}
}

const sessionRecordBusyText = "cannot verify this agent session's hook record"

// A hook cannot hold the gateway past its retry window, whatever
// retry_until it sends.
func TestForeignHookSessionRetryUntilIsBounded(t *testing.T) {
	now := time.Now()
	far := enterprisepolicy.SessionExchange{RetryUntil: now.Add(time.Hour)}
	if got := foreignHookSessionRetryUntil(far, now); !got.Equal(now.Add(foreignHookSessionRecordRetryWindow)) {
		t.Fatalf("retry_until an hour away = %v, want the %v window", got, foreignHookSessionRecordRetryWindow)
	}
	if got := foreignHookSessionRetryUntil(enterprisepolicy.SessionExchange{}, now); !got.IsZero() {
		t.Fatalf("no retry_until must mean no retry: %v", got)
	}
}
