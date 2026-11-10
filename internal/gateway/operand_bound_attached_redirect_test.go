// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestRedirectsWrittenAgainstAWordCountTowardTheOperandBound(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	defer hookpaths.HookCall()()
	request := trustedActionRequest{
		Input: actionfacts.Input{Tool: "Bash", Command: "echo x" + strings.Repeat(">f", 1500),
			CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
		Connector: "claudecode", EnforcementCapable: true,
	}
	findings := dispatchTrustedAction(withShareBodyStrict(t.Context(), func() bool { return false }), request)
	alert := false
	for _, finding := range findings {
		alert = alert || finding.RuleID == "ACTION-OPERAND-BOUND"
	}
	if action := buildVerdict(findings, "tool_call").Action; !alert || action != "alert" {
		t.Errorf("1500 adjacent file redirects: action %s, bound alert %v, findings %v", action, alert, findings)
	}
}
