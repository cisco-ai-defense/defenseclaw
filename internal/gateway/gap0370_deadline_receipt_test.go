// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestGAP0370DeadlineReceiptRecordsDeliveredAnswer(t *testing.T) {
	for _, deployment := range []string{"per_user", "managed_enterprise"} {
		for _, mode := range []string{"open", "closed"} {
			for _, proposed := range []string{"allow", "block"} {
				cfg := &config.Config{DeploymentMode: deployment}
				cfg.Guardrail.HookFailMode = mode
				api := &APIServer{scannerCfg: cfg}
				proposal := agentHookResponse{Action: proposed, Reason: "proposal", Mode: "action"}
				for _, tc := range []struct {
					receipt, want string
				}{
					{"late\n", "block"},
					{"open\n", "allow"},
					{"ack\n", proposed},
				} {
					got := api.deliveredHookDecision("claudecode", proposal, tc.receipt)
					if got.Action != tc.want {
						t.Errorf("deployment=%s mode=%s proposed=%s receipt=%q: action=%s, want %s",
							deployment, mode, proposed, tc.receipt, got.Action, tc.want)
					}
				}
			}
		}
	}
}

func TestGAP0407ReceiptDecidesAuditedActionAcrossAnswerTiming(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.scannerCfg.DeploymentMode = "per_user"
	f.offer(t, "late-after-offer", hookexec.HookDeliveryReceiptLate)
	f.offer(t, "open-after-offer", hookexec.HookDeliveryReceiptOpen)

	body := managedHookBody("late-before-offer", "PreToolUse")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(body+hookexec.HookDeliveryReceiptLate))
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)

	got := f.audited(t, "late-after-offer", "open-after-offer", "late-before-offer")
	for _, id := range []string{"late-after-offer", "late-before-offer"} {
		if !strings.HasPrefix(got[id], "block") {
			t.Errorf("%s audited %q, want the delivered block", id, got[id])
		}
	}
	if got["open-after-offer"] != "allow" {
		t.Errorf("open receipt audited %q, want the delivered allow", got["open-after-offer"])
	}
}
