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
			got := recordFromObservation(tc.obs)
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

func TestComposeBody_RedactsAccidentalSecrets(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"bearer token", "auth failed: Bearer abc123.def456.ghi789", "<redacted>"},
		{"api_key=", "api_key=sk-live-abc123", "<redacted>"},
		{"api-key=", "api-key=sk-1234", "<redacted>"},
		{"password=", "password=hunter2", "<redacted>"},
		{"token=", "token=eyJhbGciOi", "<redacted>"},
		{"benign text is untouched", "no secret here", ""},
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
