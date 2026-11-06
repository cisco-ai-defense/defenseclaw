// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
