// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestR108G501OpenClawPluginNoticeIsScopedAndOneShot(t *testing.T) {
	received := make(chan receivedRequest, 5)
	srv := startMockGW(t, rpcRecordingLoop(received))
	client := connectToMockGW(t, srv)
	s := &Sidecar{
		cfg:    &config.Config{Guardrail: config.GuardrailConfig{Connector: "openclaw"}},
		client: client, notify: NewNotificationQueue(),
		router:   &EventRouter{activeSessions: map[string]time.Time{"session-1": time.Now()}},
		alertCtx: context.Background(),
	}
	s.sendEnforcementAlert("plugin", "amazon-bedrock", "HIGH", 4, []string{"blocked"}, "plugin scan decision", "openclaw")
	if len(received) != 0 {
		t.Fatal("plugin notice was added to the durable session transcript")
	}
	first, receipt := s.notify.PrepareSystemMessage()
	if !strings.Contains(first, `Plugin "amazon-bedrock"`) || !strings.Contains(first, "Continue unrelated requests normally") ||
		strings.Contains(first, "You MUST") || len(receipt) != 1 {
		t.Fatalf("notice=%q receipt=%v", first, receipt)
	}
	s.notify.CommitSystemMessage(receipt)
	second, _ := s.notify.PrepareSystemMessage()
	if second != "" {
		t.Fatalf("notice repeated on a later request: %q", second)
	}
	if len(s.notify.ActiveNotifications()) != 0 {
		t.Fatal("consumed plugin notice remained queued")
	}
}

func TestR108G501PluginNoticeRetriesOnlyAfterInjection(t *testing.T) {
	queue := NewNotificationQueue()
	queue.Push(SecurityNotification{SubjectType: "plugin", SkillName: "sample", OneShot: true})
	first, receipt := queue.PrepareSystemMessage()
	if first == "" || len(receipt) != 1 {
		t.Fatalf("notice=%q receipt=%v", first, receipt)
	}
	if next, _ := queue.PrepareSystemMessage(); next != "" {
		t.Fatalf("reserved notice repeated: %q", next)
	}
	queue.ReleaseSystemMessage(receipt)
	if next, retry := queue.PrepareSystemMessage(); next == "" || len(retry) != 1 {
		t.Fatalf("released notice=%q receipt=%v", next, retry)
	}
}
