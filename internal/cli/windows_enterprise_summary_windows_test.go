// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The text summary of an OK status used to print only services, so an
// installed agent the enumerator could not enroll (Cursor's Agent CLI at an
// unreviewed build, say) showed only in --json. It now prints every warning
// except the internal lifecycle diagnostic.
func TestWindowsStandaloneSummaryPrintsWarnings(t *testing.T) {
	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	result.OK = true
	const unprotected = "cursor 2026.09.26-dd393fe for user alice (S-1-5-21-1-2-3-1001) is not protected: version 2026.09.26-dd393fe is not verified against a known hook contract"
	result.AddWarning(enterprisehooks.UnprotectedCodeHookContractUnverified, unprotected)
	result.AddWarning("lifecycle_diagnostic", "security descriptor detail for support")
	var out bytes.Buffer
	writeWindowsEnterpriseStandaloneSummary(&out, result)
	text := out.String()
	if !strings.Contains(text, "DefenseClaw Windows enterprise status (standalone): OK\n") {
		t.Fatalf("summary lost its state line:\n%s", text)
	}
	if !strings.Contains(text, "  warning "+enterprisehooks.UnprotectedCodeHookContractUnverified+": "+unprotected+"\n") {
		t.Fatalf("summary does not name the unprotected agent:\n%s", text)
	}
	if strings.Contains(text, "lifecycle_diagnostic") || strings.Contains(text, "security descriptor detail") {
		t.Fatalf("summary printed the internal lifecycle diagnostic:\n%s", text)
	}
}

// rotate-credentials refuses on Windows, but --help shows its help and
// exits 0 instead of the 1639 refusal.
func TestWindowsRotateCredentialsHelpIsNotRefused(t *testing.T) {
	cmd := newWindowsRotateCredentialsCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.RunE(cmd, []string{"--help"}); err != nil || !strings.Contains(out.String(), "rotate-credentials") {
		t.Fatalf("--help: err=%v output=%q", err, out.String())
	}
	if err := cmd.RunE(cmd, nil); commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs {
		t.Fatalf("rotate-credentials exit = %d (%v), want %d", commandExitCode(err), err, enterprisestatus.WindowsExitInvalidArgs)
	}
}
