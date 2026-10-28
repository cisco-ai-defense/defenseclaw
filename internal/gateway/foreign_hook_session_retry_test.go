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

// GAP-1813: a try the gateway itself held up past an allow's hold (a
// stalled disk or process at a cold start) is applied again at once while
// the hook still waits, even when the stall used up retry_until. Before, the
// stalled try's unavailable answer was final, and a clean call was denied
// with "cannot verify this agent session's hook record" (D11 on ewin3,
// 2.66 s). An old hook (no retry_until) still gets the first answer.
func TestForeignHookSessionGatewayAppliesAStalledCleanScanAgain(t *testing.T) {
	foreignHookGuardianDirForTest(t)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	identity := foreignHookTestIdentities(1)[0]
	previousLock, previousAudit, previousHold, previousLog := foreignHookAccountExchangeLock, foreignHookSessionDenialAudit, foreignHookExchangeHold, foreignHookSessionRetryLog
	t.Cleanup(func() {
		foreignHookAccountExchangeLock, foreignHookSessionDenialAudit, foreignHookExchangeHold, foreignHookSessionRetryLog = previousLock, previousAudit, previousHold, previousLog
	})
	foreignHookExchangeHold = 300 * time.Millisecond
	var audited, logged []string
	foreignHookSessionDenialAudit = func(_ *APIServer, _ context.Context, _ string, _ enterprisepolicy.SessionExchange, decision enterprisepolicy.GuardDecision) {
		audited = append(audited, decision.Reason)
	}
	foreignHookSessionRetryLog = func(_ string, _ int, why string) { logged = append(logged, why) }
	for _, tc := range []struct {
		name      string
		retry     bool
		late      bool // retry_until already past when the exchange arrives; the first try is quick
		wantAllow bool
		wantCalls int
	}{
		{"stalled past retry_until, then allowed", true, false, true, 2},
		{"retry_until used up before the first try, then allowed", true, true, true, 2},
		{"hook sends no retry_until", false, false, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audited, logged = nil, nil
			calls := 0
			foreignHookAccountExchangeLock = func(ctx context.Context, dataDir, identity string) (func(), error) {
				calls++
				if calls == 1 {
					if !tc.late {
						time.Sleep(foreignHookExchangeHold + 50*time.Millisecond)
					}
					return nil, errors.New("lock unavailable")
				}
				return previousLock(ctx, dataDir, identity)
			}
			body := `{"key":{"connector":"claudecode","session":"s-stall","process":"` + runtime.GOOS + `:b:4243:100"},"session_start":false,"decision":{"deny":false}`
			if tc.retry {
				// The stall outlasts the hook's whole retry window, or (late)
				// the gateway used it up before the exchange was read.
				until := time.Now().Add(100 * time.Millisecond)
				if tc.late {
					until = time.Now().Add(-50 * time.Millisecond)
				}
				body += `,"retry_until":"` + until.UTC().Format(time.RFC3339Nano) + `"`
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", strings.NewReader(body+"}"))
			ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
			ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
			response := newDeadlineRecorder()
			api.handleForeignHookSession(response, req.WithContext(ctx))
			got := response.Body.String()
			if response.Code != http.StatusOK {
				t.Fatalf("status %d: %s", response.Code, got)
			}
			if tc.wantAllow != strings.Contains(got, `"deny":false`) || calls != tc.wantCalls {
				t.Fatalf("allow=%v after %d tries (want allow=%v after %d): %s", !tc.wantAllow, calls, tc.wantAllow, tc.wantCalls, got)
			}
			if tc.wantAllow && (len(audited) != 0 || len(logged) != 1 || logged[0] != "stalled") {
				t.Fatalf("an allowed retry leaves no audit row and one log line: audited %v, logged %v", audited, logged)
			}
			if !tc.wantAllow && len(audited) != 1 {
				t.Fatalf("a final denial is audited once: %v", audited)
			}
		})
	}
}
