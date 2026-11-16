// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

func unauthorizedGateway(until int) *stubRT {
	return &stubRT{onRequest: func(rt *stubRT, _ *http.Request) (*http.Response, error) {
		if until > 0 && rt.requests > until {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"action":"allow"}`)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(`{"error":"unauthorized"}`)), Header: make(http.Header)}, nil
	}}
}

func captureUnenrolledReports(t *testing.T) *[]refusalpipe.Report {
	t.Helper()
	var reports []refusalpipe.Report
	restore := sendUnenrolledRefusal
	sendUnenrolledRefusal = func(_ context.Context, report refusalpipe.Report) error {
		reports = append(reports, report)
		return nil
	}
	t.Cleanup(func() { sendUnenrolledRefusal = restore })
	return &reports
}

// GAP-0722: the first call of a new Windows standalone account meets a 401
// until the gateway names the account, which can outlast the resends. It was
// refused with "an answer DefenseClaw could not use" and no audit row; it
// now says the credentials are not accepted yet, with the wait, and reports
// the refusal so the account has a row. It stays blocked in every fail mode.
func TestWindowsStandaloneFirstCallMeetingA401NamesThePendingCredentials(t *testing.T) {
	shortAuthRetryDelay(t)
	for _, tc := range []struct{ connector, event, stdin string }{
		{"claudecode", "UserPromptSubmit", `{"hook_event_name":"UserPromptSubmit","prompt":"hello"}`},
		{"codex", "PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`},
	} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(tc.connector+"/"+mode, func(t *testing.T) {
				reports := captureUnenrolledReports(t)
				rt := unauthorizedGateway(0)
				result := run(t, tc.connector, rt, func(o *Options) {
					managedCodex(o)
					o.ExplainUnenrolledAccount = true
					o.FailMode = mode
					o.Event = tc.event
					o.Stdin = strings.NewReader(tc.stdin)
				})
				text := result.stdout + result.stderr
				if !blocked(result) || rt.requests != hookAuthRetries+1 {
					t.Fatalf("blocked=%v requests=%d, want a block after %d sends: %q", blocked(result), rt.requests, hookAuthRetries+1, text)
				}
				if !strings.Contains(text, "has not accepted the credentials of this account yet") || !strings.Contains(text, "Try again in a minute or two") ||
					strings.Contains(text, "could not use") {
					t.Errorf("text = %q, want the pending-credentials cause and wait", text)
				}
				if len(*reports) != 1 || (*reports)[0].Reason != managedCredentialPendingReason || (*reports)[0].Connector != tc.connector {
					t.Fatalf("reports = %+v, want one credential-pending refusal report", *reports)
				}
				if _, ok := (*reports)[0].Normalize(); !ok {
					t.Errorf("the gateway refusal pipe would drop the report: %+v", (*reports)[0])
				}
			})
		}
	}
}

// The call the gateway accepts within the resends stays allowed, and the
// other authentication refusals keep their text: a 403, and a 401 for a
// hook that is not on a Windows standalone account.
func TestCredentialPendingTextIsOnlyForTheWindowsStandalone401(t *testing.T) {
	shortAuthRetryDelay(t)
	reports := captureUnenrolledReports(t)
	allowed := run(t, "codex", unauthorizedGateway(2), func(o *Options) {
		managedCodex(o)
		o.ExplainUnenrolledAccount = true
	})
	if blocked(allowed) || allowed.rt.requests != 3 || len(*reports) != 0 {
		t.Fatalf("a 401 that clears within the resends: blocked=%v requests=%d reports=%+v stdout=%q stderr=%q", blocked(allowed), allowed.rt.requests, *reports, allowed.stdout, allowed.stderr)
	}
	for name, mutate := range map[string]func(*Options){
		"not a Windows standalone hook": func(o *Options) { managedCodex(o) },
		"secure client":                 func(o *Options) { managedCodex(o); o.SecureClient = true },
	} {
		result := run(t, "codex", unauthorizedGateway(0), func(o *Options) { mutate(o); o.FailMode = "closed" })
		if strings.Contains(result.stdout+result.stderr, "has not accepted the credentials") {
			t.Errorf("%s: carries the pending-credentials text: %q", name, result.stdout+result.stderr)
		}
	}
	forbidden := run(t, "codex", &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(`{"error":"forbidden"}`)), Header: make(http.Header)}, nil
	}}, func(o *Options) { managedCodex(o); o.ExplainUnenrolledAccount = true })
	if !blocked(forbidden) || strings.Contains(forbidden.stdout+forbidden.stderr, "has not accepted the credentials") {
		t.Errorf("HTTP 403: blocked=%v text=%q", blocked(forbidden), forbidden.stdout+forbidden.stderr)
	}
	if len(*reports) != 0 {
		t.Errorf("unexpected reports: %+v", *reports)
	}
}
