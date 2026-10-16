// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0555: an account in enterprise.enrollment.exempt_users ran host Claude
// Code (the hook allowed it) while its explain said "claude and codex run
// only in a sandbox on this computer". The explain, the wrapper receipt and
// the doctor now take the host-run answer from the managed gateway's
// exemption; a non-exempt account's text is unchanged.
func TestManagedExplainOfAnExemptAccount(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	rows := func(exempt bool) string {
		m := managedExplainFixture() // requires claudecode and codex
		m.EnrollmentExempt = exempt
		m.HostRunGate = "refused"
		if exempt {
			m.HostRunGate = "exempt"
		}
		var b strings.Builder
		for _, r := range managedExplainRows(m, now) {
			b.WriteString(r.label + " | " + r.text + "\n")
		}
		return b.String()
	}
	exempt := rows(true)
	has(t, exempt, "Required | your account is exempt from enrollment (enterprise.enrollment.exempt_users), so required_for doesn't apply to you: "+
		"claude and codex may also run on this computer outside a sandbox")
	lacks(t, exempt, "run only in a sandbox on this computer")
	has(t, rows(false), "Required | claude and codex run only in a sandbox on this computer")
	m := managedExplainFixture()
	m.Allowed = false
	m.HostRunGate = "exempt"
	var b strings.Builder
	for _, r := range managedExplainRows(m, now) {
		b.WriteString(r.label + " | " + r.text + "\n")
	}
	has(t, b.String(), "Required | your account is exempt from enrollment")
	has(t, b.String(), "may run on this computer outside a sandbox")
}

func TestManagedWrapperAndDoctorOfAnExemptAccount(t *testing.T) {
	status := managedStatusOfExplain(&sandboxapi.ManagedExplain{Profile: "contractors", Description: "Coding agents only in a sandbox.",
		RequiredFor: []string{"claudecode"}, EnrollmentExempt: true, HostRunGate: "exempt"})
	has(t, managedPolicyLine(status), "required_for does not apply and a host run is allowed")
	// The receipt offers the one-time bypass: the hook allows the host run.
	ta := managedTestApp(t, "claudecode")
	ta.daemon.explain.Managed.EnrollmentExempt = true
	ta.daemon.explain.Managed.HostRunGate = "exempt"
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "claude"}))
	has(t, ta.output(), "bypass once: DEFENSECLAW_NO_SANDBOX=1 claude")

	// The doctor names the bypass for the required agent too.
	ta = newTestApp(t, "")
	writeConfig(t, ta, "")
	bin := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	if err := os.WriteFile(bin, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	ta.Executable = func() (string, error) { return bin, nil }
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "claude", Shell: "bash"}))
	ta.daemon.explain.Managed = managedExplainFixture() // requires claudecode and codex
	lacks(t, ta.wrappersCheck(bg, true).Detail, "DEFENSECLAW_NO_SANDBOX")
	ta.daemon.explain.Managed.EnrollmentExempt = true
	ta.daemon.explain.Managed.HostRunGate = "exempt"
	has(t, ta.wrappersCheck(bg, true).Detail, "(DEFENSECLAW_NO_SANDBOX=1 runs claude on the host)")
}
