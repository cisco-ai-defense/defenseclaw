// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/notify"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

func TestRecordFromObservation_Mapping(t *testing.T) {
	cases := []struct {
		name        string
		obs         notifier.Observation
		wantSev     pb.NotificationSeverity
		wantPres    pb.NotificationPresentation
		wantTitle   string
		wantBodySub string // substring assertion, tolerates redaction
	}{
		{
			name: "block → ERROR TRANSIENT_AND_HISTORY",
			obs: notifier.Observation{
				Category:     notifier.CategoryBlock,
				Source:       notifier.SourceHook,
				Notification: notify.Notification{Title: "DefenseClaw blocked bash", Body: "dangerous command"},
			},
			wantSev:     pb.NotificationSeverity_NOTIFICATION_SEVERITY_ERROR,
			wantPres:    pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY,
			wantTitle:   "DefenseClaw blocked bash",
			wantBodySub: "dangerous",
		},
		{
			name: "would_block → WARNING TRANSIENT_AND_HISTORY",
			obs: notifier.Observation{
				Category:     notifier.CategoryWouldBlock,
				Notification: notify.Notification{Title: "DefenseClaw would block gpt-4o", Body: "observe mode"},
			},
			wantSev:  pb.NotificationSeverity_NOTIFICATION_SEVERITY_WARNING,
			wantPres: pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY,
		},
		{
			name: "approval → WARNING TRANSIENT",
			obs: notifier.Observation{
				Category:     notifier.CategoryApproval,
				Notification: notify.Notification{Title: "Approval needed: git push", Body: "reply in chat"},
			},
			wantSev:  pb.NotificationSeverity_NOTIFICATION_SEVERITY_WARNING,
			wantPres: pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT,
		},
		{
			name: "service_state → WARNING TRANSIENT",
			obs: notifier.Observation{
				Category:     notifier.CategoryServiceState,
				Notification: notify.Notification{Title: "DefenseClaw protection paused", Body: "connection lost"},
			},
			wantSev:  pb.NotificationSeverity_NOTIFICATION_SEVERITY_WARNING,
			wantPres: pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT,
		},
		{
			name: "empty title falls back to a safe default",
			obs: notifier.Observation{
				Category:     notifier.CategoryBlock,
				Notification: notify.Notification{Body: "something"},
			},
			wantSev:   pb.NotificationSeverity_NOTIFICATION_SEVERITY_ERROR,
			wantPres:  pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY,
			wantTitle: "DefenseClaw notification",
		},
		{
			name: "unknown category is dropped",
			obs: notifier.Observation{
				Category:     notifier.Category("mystery"),
				Notification: notify.Notification{Title: "X"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Unmanaged path: recordFromObservation preserves the
			// composeTitle/composeBody flow that shares strings with
			// the OS toast surface. The managed_enterprise copy
			// contract is exercised separately by
			// TestRecordFromObservation_ManagedCopy below.
			got := recordFromObservation(tc.obs, false)
			if tc.wantSev == 0 && tc.wantPres == 0 && tc.wantTitle == "" {
				if got != nil {
					t.Fatalf("expected nil record for unknown category, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected non-nil record for %q", tc.name)
			}
			if got.Severity != tc.wantSev {
				t.Errorf("severity: got %v want %v", got.Severity, tc.wantSev)
			}
			if got.Presentation != tc.wantPres {
				t.Errorf("presentation: got %v want %v", got.Presentation, tc.wantPres)
			}
			if tc.wantTitle != "" && got.Title != tc.wantTitle {
				t.Errorf("title: got %q want %q", got.Title, tc.wantTitle)
			}
			if tc.wantBodySub != "" && !strings.Contains(got.Body, tc.wantBodySub) {
				t.Errorf("body: %q missing substring %q", got.Body, tc.wantBodySub)
			}
			if got.SchemaVersion != schemaVersion {
				t.Errorf("schema version: got %d want %d", got.SchemaVersion, schemaVersion)
			}
		})
	}
}

// TestRecordFromObservation_ManagedCopy pins the two-surface AVC copy
// contract for managed_enterprise: title short (pop-up) + body
// detailed (message history). Every branch of composeManaged is
// exercised with a concrete expected string so future edits to the
// copy surface here first.
func TestRecordFromObservation_ManagedCopy(t *testing.T) {
	aidReason := "Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION, Prompt Injection, PII"

	cases := []struct {
		name      string
		obs       notifier.Observation
		wantTitle string
		wantBody  string
	}{
		{
			name: "block with AID reason renders human copy",
			obs: notifier.Observation{
				Category:     notifier.CategoryBlock,
				Notification: notify.Notification{Title: "raw title", Body: aidReason},
			},
			wantTitle: "DefenseClaw blocked the request",
			wantBody:  "The request was blocked for security violation and privacy violation and the following signals: Prompt Injection, PII",
		},
		{
			name: "block with only categories (no signals) drops the signals clause",
			obs: notifier.Observation{
				Category:     notifier.CategoryBlock,
				Notification: notify.Notification{Body: "Cisco AI Defense: SAFETY_VIOLATION"},
			},
			wantTitle: "DefenseClaw blocked the request",
			wantBody:  "The request was blocked for safety violation",
		},
		{
			name: "block with three categories uses Oxford-comma join",
			obs: notifier.Observation{
				Category: notifier.CategoryBlock,
				Notification: notify.Notification{
					Body: "Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION, SAFETY_VIOLATION",
				},
			},
			wantTitle: "DefenseClaw blocked the request",
			wantBody:  "The request was blocked for security violation, privacy violation, and safety violation",
		},
		{
			name: "block without AID prefix falls back to policy-violation copy",
			obs: notifier.Observation{
				Category:     notifier.CategoryBlock,
				Notification: notify.Notification{Body: "hook guardian: connector cursor rejected shell execution"},
			},
			wantTitle: "DefenseClaw blocked the request",
			wantBody:  "The request was blocked for a policy violation",
		},
		{
			name: "block with unmapped AID token falls back to mechanical humanize",
			obs: notifier.Observation{
				Category:     notifier.CategoryBlock,
				Notification: notify.Notification{Body: "Cisco AI Defense: NEW_CATEGORY_X"},
			},
			wantTitle: "DefenseClaw blocked the request",
			wantBody:  "The request was blocked for new category x",
		},
		{
			name: "would-block appends observe-mode tail",
			obs: notifier.Observation{
				Category:     notifier.CategoryWouldBlock,
				Notification: notify.Notification{Body: aidReason},
			},
			wantTitle: "DefenseClaw would have blocked the request",
			wantBody:  "The request would have been blocked for security violation and privacy violation and the following signals: Prompt Injection, PII (observe mode: no enforcement taken)",
		},
		{
			name: "would-ask swaps the title verb",
			obs: notifier.Observation{
				Category:     notifier.CategoryWouldBlock,
				Notification: notify.Notification{Body: "Cisco AI Defense: SECURITY_VIOLATION"},
				Event:        notifier.BlockEvent{WouldAsk: true},
			},
			wantTitle: "DefenseClaw would have asked about the request",
			wantBody:  "The request would have been asked about for security violation (observe mode: no enforcement taken)",
		},
		{
			name: "approval renders subject + reason",
			obs: notifier.Observation{
				Category: notifier.CategoryApproval,
				Notification: notify.Notification{
					Title: "raw title", Body: "unused",
				},
				Event: notifier.ApprovalEvent{
					Subject: "git push to main",
					Reason:  "destructive git operation",
				},
			},
			wantTitle: "DefenseClaw needs your approval",
			wantBody:  "Reply in your chat to approve or deny: git push to main flagged for destructive git operation",
		},
		{
			name: "approval falls back to generic subject/reason when payload is missing",
			obs: notifier.Observation{
				Category:     notifier.CategoryApproval,
				Notification: notify.Notification{},
			},
			wantTitle: "DefenseClaw needs your approval",
			wantBody:  "Reply in your chat to approve or deny: an agent action flagged for policy review",
		},
		{
			name: "service_state disconnected keeps existing title verbatim and prefixes reason",
			obs: notifier.Observation{
				Category:     notifier.CategoryServiceState,
				Notification: notify.Notification{Title: "DefenseClaw protection paused"},
				Event: notifier.ServiceStateEvent{
					State:  notifier.ServiceStateDisconnected,
					Reason: "connection lost",
				},
			},
			wantTitle: "DefenseClaw protection paused",
			wantBody:  "Reason: connection lost",
		},
		{
			name: "service_state reconnected keeps existing title verbatim",
			obs: notifier.Observation{
				Category:     notifier.CategoryServiceState,
				Notification: notify.Notification{Title: "DefenseClaw protection restored"},
				Event: notifier.ServiceStateEvent{
					State:  notifier.ServiceStateReconnected,
					Reason: "protocol negotiated",
				},
			},
			wantTitle: "DefenseClaw protection restored",
			wantBody:  "Reason: protocol negotiated",
		},
		{
			name: "service_state without a reason gives an empty body",
			obs: notifier.Observation{
				Category:     notifier.CategoryServiceState,
				Notification: notify.Notification{Title: "DefenseClaw protection paused"},
				Event: notifier.ServiceStateEvent{
					State: notifier.ServiceStateDisconnected,
				},
			},
			wantTitle: "DefenseClaw protection paused",
			wantBody:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := recordFromObservation(tc.obs, true)
			if got == nil {
				t.Fatalf("expected non-nil record for %q", tc.name)
			}
			if got.Title != tc.wantTitle {
				t.Errorf("title:\n  got  %q\n  want %q", got.Title, tc.wantTitle)
			}
			if got.Body != tc.wantBody {
				t.Errorf("body:\n  got  %q\n  want %q", got.Body, tc.wantBody)
			}
			if got.SchemaVersion != schemaVersion {
				t.Errorf("schema version: got %d want %d", got.SchemaVersion, schemaVersion)
			}
		})
	}
}

// TestManagedCopy_SecretSweepStillFires proves the paranoid secret
// redaction runs on the managed copy path too — the copy rework
// must not bypass the wire-contract's "no credentials in a body"
// invariant.
func TestManagedCopy_SecretSweepStillFires(t *testing.T) {
	// Approval body embeds a subject that happens to contain a
	// bearer-token shape. The paranoid sweep at composeManaged's
	// final step must redact it before the record leaves the bridge.
	obs := notifier.Observation{
		Category:     notifier.CategoryApproval,
		Notification: notify.Notification{},
		Event: notifier.ApprovalEvent{
			Subject: "curl -H 'Authorization: Bearer sk-abc123deadbeef' https://api.example",
			Reason:  "outbound HTTP call",
		},
	}
	got := recordFromObservation(obs, true)
	if got == nil {
		t.Fatal("expected non-nil record")
	}
	if strings.Contains(got.Body, "sk-abc123deadbeef") {
		t.Fatalf("managed-copy body leaked a token: %q", got.Body)
	}
	if !strings.Contains(got.Body, "<redacted>") {
		t.Fatalf("managed-copy body missing <redacted> marker: %q", got.Body)
	}
}

// TestParseAIDReason exercises the split rule between category
// tokens (SCREAMING_SNAKE_CASE) and signal tokens (rule names).
// Split must stay in lockstep with compactAIDCategories (see
// TestCompactAIDCategories) since both paths key on the same
// prefix + regex.
func TestParseAIDReason(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantCats []string
		wantSigs []string
	}{
		{
			name:     "mixed categories and signals",
			in:       "Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION, Prompt Injection, PII",
			wantCats: []string{"SECURITY_VIOLATION", "PRIVACY_VIOLATION"},
			wantSigs: []string{"Prompt Injection", "PII"},
		},
		{
			name:     "categories only",
			in:       "Cisco AI Defense: SAFETY_VIOLATION",
			wantCats: []string{"SAFETY_VIOLATION"},
			wantSigs: nil,
		},
		{
			name:     "signals only",
			in:       "Cisco AI Defense: Prompt Injection, PII",
			wantCats: nil,
			wantSigs: []string{"Prompt Injection", "PII"},
		},
		{
			name:     "non-AID body returns empty",
			in:       "hook guardian: connector cursor rejected shell execution",
			wantCats: nil,
			wantSigs: nil,
		},
		{
			name:     "empty tail returns empty",
			in:       "Cisco AI Defense:",
			wantCats: nil,
			wantSigs: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCats, gotSigs := parseAIDReason(tc.in)
			if !stringSlicesEqual(gotCats, tc.wantCats) {
				t.Errorf("categories: got %v want %v", gotCats, tc.wantCats)
			}
			if !stringSlicesEqual(gotSigs, tc.wantSigs) {
				t.Errorf("signals: got %v want %v", gotSigs, tc.wantSigs)
			}
		})
	}
}

// TestHumanizeAIDCategory covers both the curated-map path and the
// mechanical fallback. A regression that dropped the fallback would
// make new AID categories render as raw SCREAMING_SNAKE_CASE tokens
// in end-user notifications.
func TestHumanizeAIDCategory(t *testing.T) {
	cases := map[string]string{
		"SECURITY_VIOLATION":    "security violation",
		"PRIVACY_VIOLATION":     "privacy violation",
		"SAFETY_VIOLATION":      "safety violation",
		"PROMPT_INJECTION":      "prompt injection",
		"NONE_ATTACK_TECHNIQUE": "policy violation",
		"LOW_SEVERITY":          "low-severity policy signal",
		"NEW_CATEGORY_X":        "new category x", // mechanical fallback
		"SINGLE":                "single",         // fallback without underscores
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			if got := humanizeAIDCategory(in); got != want {
				t.Errorf("humanizeAIDCategory(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

// TestHumanCategoryList pins the English-style join semantics: 1
// item verbatim, 2 items joined with "and" (no Oxford comma), 3+
// items joined with commas + Oxford comma. The exact output shape
// is what end users read on the wire, so a regression here changes
// customer-facing copy.
func TestHumanCategoryList(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"empty falls back to policy violation", nil, "a policy violation"},
		{"one item verbatim", []string{"security violation"}, "security violation"},
		{"two items joined with and", []string{"security violation", "privacy violation"}, "security violation and privacy violation"},
		{"three items uses Oxford comma", []string{"security violation", "privacy violation", "safety violation"}, "security violation, privacy violation, and safety violation"},
		{"four items uses Oxford comma", []string{"a", "b", "c", "d"}, "a, b, c, and d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := humanCategoryList(tc.in); got != tc.want {
				t.Errorf("humanCategoryList(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestComposeBody_RedactsAccidentalSecrets(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // empty → assert no redaction happened
	}{
		{"bearer token", "auth failed: Bearer abc123.def456.ghi789", "<redacted>"},
		{"authorization basic", "Authorization: Basic dXNlcjpwYXNzd29yZA==", "<redacted>"},
		{"api_key=", "api_key=sk-live-abc123", "<redacted>"},
		{"api-key=", "api-key=sk-1234", "<redacted>"},
		{"apikey (no separator)", "apikey=sk-1234", "<redacted>"},
		{"password=", "password=hunter2", "<redacted>"},
		{"password: colon", "password: hunter2", "<redacted>"},
		{"token=", "token=eyJhbGciOi", "<redacted>"},
		{"secret=", "secret=topsecret123", "<redacted>"},
		{"passphrase=", "passphrase=corny-horse-battery-staple", "<redacted>"},
		{"aws access key id", "session id AKIAIOSFODNN7EXAMPLE was denied", "<redacted>"},
		{"jwt bare", "cookie: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoaSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "<redacted>"},
		{"pem private key opener", "-----BEGIN RSA PRIVATE KEY-----", "<redacted>"},
		{"benign text is untouched", "no secret here", ""},
		{"the word secret alone is not redacted", "keep this secret in mind", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := composeBody(notifier.Observation{
				Notification: notify.Notification{Body: tc.body},
			})
			if tc.want == "" {
				if strings.Contains(body, "<redacted>") {
					t.Errorf("expected untouched, got %q", body)
				}
				return
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("expected %q in body %q", tc.want, body)
			}
		})
	}
}
