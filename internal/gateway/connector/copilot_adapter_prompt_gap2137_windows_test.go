// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gap2137Replacement is the closed adapter's answer to a Copilot CLI prompt,
// written out so the test also runs on the template before the fix.
const gap2137Replacement = `{"modifiedTransformedPrompt":"DefenseClaw blocked the current user message. Do not answer it or call tools for it. ` +
	`Reply only: DefenseClaw blocked this prompt: its DefenseClaw hook failed closed."}`

const gap2137PromptPayload = `{"sessionId":"s1","prompt":"hi","transformedPrompt":"hi"}`

// GAP-2137: when the Windows adapter itself fails closed (the launcher is
// missing, crashes without an answer, or times out), a Copilot CLI prompt
// (userPromptTransformed) is replaced with DefenseClaw's notice, as the
// native hook and the shell hooks answer a closed failure (GAP-2131). Before
// the fix the adapter wrote a denial only for preToolUse and
// permissionRequest, so the prompt reached the model unchecked.
func TestGAP2137CopilotAdapterFailureReplacesAPromptWhenClosed(t *testing.T) {
	missing := renderCopilotAdapterForTest(t, filepath.Join(t.TempDir(), "missing-hook.exe"), 10_000, "closed")
	stdout, stderr, code := runCopilotAdapterTest(t, missing, gap2137PromptPayload, "userPromptTransformed")
	if code != 0 || strings.TrimSpace(stdout) != gap2137Replacement || !strings.Contains(stderr, "Copilot hook adapter failed closed") {
		t.Errorf("missing launcher: exit %d stdout %q stderr %q, want the prompt replaced", code, stdout, stderr)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(copilotAdapterHelperMode, "crash")
	crashing := renderCopilotAdapterForTest(t, executable, 10_000, "closed")
	stdout, stderr, code = runCopilotAdapterTest(t, crashing, gap2137PromptPayload, "userPromptTransformed")
	if code != 0 || strings.TrimSpace(stdout) != gap2137Replacement {
		t.Errorf("crashed launcher: exit %d stdout %q stderr %q, want the prompt replaced", code, stdout, stderr)
	}
	t.Setenv(copilotAdapterHelperMode, "timeout")
	slow := renderCopilotAdapterForTest(t, executable, 1_500, "closed")
	stdout, stderr, code = runCopilotAdapterTest(t, slow, gap2137PromptPayload, "userPromptTransformed")
	if code != 0 || strings.TrimSpace(stdout) != gap2137Replacement || !strings.Contains(stderr, "timed out") {
		t.Errorf("launcher timeout: exit %d stdout %q stderr %q, want the prompt replaced", code, stdout, stderr)
	}
	// A tool call keeps its denial, and other prompt events stay silent.
	stdout, _, code = runCopilotAdapterTest(t, missing, `{"source":"copilot-adapter-probe"}`)
	if code != 0 || strings.TrimSpace(stdout) != copilotAdapterClosedDenial {
		t.Errorf("missing launcher, preToolUse: exit %d stdout %q, want Copilot's denial", code, stdout)
	}
	stdout, _, code = runCopilotAdapterTest(t, missing, gap2137PromptPayload, "userPromptSubmitted")
	if code != 0 || strings.TrimSpace(stdout) != "" {
		t.Errorf("missing launcher, userPromptSubmitted: exit %d stdout %q, want nothing", code, stdout)
	}
}

// GAP-2137: an open adapter still lets the prompt through on its own
// failure, except during an install or upgrade, when the prompt is replaced
// with the install notice as a tool call is denied.
func TestGAP2137CopilotAdapterOpenFailureAndInstallWindow(t *testing.T) {
	adapter := renderCopilotAdapterForTest(t, filepath.Join(t.TempDir(), "missing-hook.exe"), 10_000, "open")
	stdout, stderr, code := runCopilotAdapterTest(t, adapter, gap2137PromptPayload, "userPromptTransformed")
	if code != 0 || stdout != "" || !strings.Contains(stderr, "Copilot hook adapter failed open") {
		t.Errorf("open: exit %d stdout %q stderr %q, want the prompt through with the diagnostic", code, stdout, stderr)
	}
	if err := os.Mkdir(filepath.Join(filepath.Dir(filepath.Dir(adapter)), ".install.lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCopilotAdapterTest(t, adapter, gap2137PromptPayload, "userPromptTransformed")
	if code != 0 || !strings.HasPrefix(strings.TrimSpace(stdout), `{"modifiedTransformedPrompt":"DefenseClaw blocked the current user message.`) ||
		!strings.Contains(stdout, "being installed or upgraded") {
		t.Errorf("install window: exit %d stdout %q stderr %q, want the prompt replaced with the install notice", code, stdout, stderr)
	}
}
