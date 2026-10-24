// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestR104PrivateKeyFindingUsesCatalogSeverity(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	request := trustedActionRequest{Input: actionfacts.Input{
		Tool: "Bash", Command: `cat ~/.ssh/id_ed25519`, CWD: cwd, ActiveHome: home,
	}, EnforcementCapable: true}
	generation := &compiledRulePackCategories{categories: []ruleCategory{{
		Name: "sensitive-path", Rules: []PatternRule{{
			ID: "PATH-SSH-KEY", Title: "SSH private key", Severity: "HIGH", Confidence: 0.9,
		}},
	}}}
	for _, initial := range [][]RuleFinding{nil, {{RuleID: "PATH-SSH-KEY", Severity: "LOW"}}} {
		findings := appendTrustedPrivateKeyReaderFinding(initial, generation, request, actionfacts.Facts{})
		if len(findings) != 1 || findings[0].Severity != "HIGH" {
			t.Fatalf("finding=%+v, want catalog severity HIGH", findings)
		}
	}
}
