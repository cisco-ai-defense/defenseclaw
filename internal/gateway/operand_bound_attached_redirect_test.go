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
		alert = alert || operandBoundTruncated(finding)
	}
	if action := operandBoundTierAction(findings, false); !alert || action != "alert" {
		t.Errorf("1500 adjacent file redirects: action %s, bound alert %v, findings %v", action, alert, findings)
	}
}

// Bash writes the file of >&word and 1>&word, so such targets count toward
// the call bound like those of > (GAP-2143); descriptor copies do not.
func TestFileRedirectsOfADescriptorOperatorCountTowardTheOperandBound(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, tc := range []struct {
		name, command string
		strict        bool
		action        string
		alert         bool
	}{
		{"both streams", "echo x" + strings.Repeat(" >&f", 1500), false, "alert", true},
		{"stdout", "echo x" + strings.Repeat(" 1>&f", 1500), false, "alert", true},
		{"attached", "echo x" + strings.Repeat(">&f", 1500), false, "alert", true},
		{"both streams, strict", "echo x" + strings.Repeat(" >&f", 1500), true, "block", true},
		{"stdout, strict", "echo x" + strings.Repeat(" 1>&f", 1500), true, "block", true},
		// Descriptor copies name no file, so they never reach the operand
		// bound (no operand-bound alert); 1500 of them pass the action
		// analysis node bound, which is the unknown tier of the pack for any
		// call (rel-1-0-10:GAP-0688): an alert in default, a block in strict.
		{"descriptor copies", "echo x" + strings.Repeat(" 2>&1", 1500), false, "alert", false},
		{"descriptor copies, strict", "echo x" + strings.Repeat(" >&2", 1500), true, "block", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer hookpaths.HookCall()()
			request := trustedActionRequest{Input: actionfacts.Input{
				Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
			}, Connector: "claudecode", EnforcementCapable: true, StrictPolicy: tc.strict}
			findings := dispatchTrustedAction(withShareBodyStrict(t.Context(), func() bool { return tc.strict }), request)
			alert := false
			for _, finding := range findings {
				alert = alert || operandBoundTruncated(finding)
			}
			if action := operandBoundTierAction(findings, tc.strict); action != tc.action || alert != tc.alert {
				t.Errorf("action %s, bound alert %v, findings %v; want %s, alert %v", action, alert, findings, tc.action, tc.alert)
			}
		})
	}
}
