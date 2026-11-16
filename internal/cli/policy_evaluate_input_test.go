// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestPolicyEvaluateRejectsInvalidInputsBeforeEvaluation(t *testing.T) {
	setPolicyPathTestConfig(t, &config.Config{PolicyDir: t.TempDir()})
	setPolicyPathTestFlags(t)
	for _, tc := range []struct{ flag, value string }{
		{"severity", "typo"}, {"target-type", "typo"}, {"findings", "-1"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			setPolicyPathTestFlag(t, policyEvaluateCmd, tc.flag, tc.value)
			out, err := capturePolicyPathTestOutput(t, func() error { return policyEvaluateCmd.RunE(policyEvaluateCmd, nil) })
			if err == nil || commandExitCode(err) != 2 || !strings.Contains(err.Error(), "--"+tc.flag) || out != "" {
				t.Fatalf("invalid --%s: output %q, error %v", tc.flag, out, err)
			}
		})
	}
}
