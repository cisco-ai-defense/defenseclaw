// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1973, GAP-1983: a Codex app-server that exits before answering (its
// state runtime is unusable while a Codex session that hit a full disk is
// open) no longer aborts the gateway start when an earlier setup admitted the
// hooks; the system requirements file still decides. Without that earlier
// admission Setup refuses unchanged and says what to do.
func TestCodexPolicyAppServerNoAnswerKeepsAdmittedHooks(t *testing.T) {
	previousInspector, previousPath, previousOut := codexPolicyInspector, codexSystemRequirementsPathForInspection, codexPolicyWarningOutput
	t.Cleanup(func() {
		codexPolicyInspector, codexSystemRequirementsPathForInspection, codexPolicyWarningOutput = previousInspector, previousPath, previousOut
	})
	if _, err := waitCodexRPC(context.Background(), closedCodexRPCEvents(), 1); !errors.Is(err, errCodexAppServerNoAnswer) {
		t.Fatalf("closed stream = %v, want errCodexAppServerNoAnswer", err)
	}
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{}, fmt.Errorf("codex configRequirements/read: read app-server response: EOF (%w)", errCodexAppServerNoAnswer)
	}
	requirements := filepath.Join(t.TempDir(), "requirements.toml")
	codexSystemRequirementsPathForInspection = func() (string, error) { return requirements, nil }
	var warning bytes.Buffer
	codexPolicyWarningOutput = &warning
	dir := t.TempDir()
	opts := SetupOpts{DataDir: dir}

	err := enforceCodexUserHookPolicy(context.Background(), opts)
	if !errors.Is(err, ErrSetupRefusedUnchanged) || !strings.Contains(err.Error(), "quit it, then run: defenseclaw-gateway restart") {
		t.Fatalf("no earlier admission = %v, want an unchanged refusal with the next step", err)
	}

	if err := SaveHookContractLockEntry(dir, HookContractLockEntry{Connector: "codex"}); err != nil {
		t.Fatal(err)
	}
	if err := enforceCodexUserHookPolicy(context.Background(), opts); err != nil {
		t.Fatalf("earlier admission = %v, want the gateway to keep enforcing", err)
	}
	if !strings.Contains(warning.String(), "kept enforcing the hooks an earlier setup admitted") {
		t.Fatalf("warning = %q", warning.String())
	}

	if err := os.WriteFile(requirements, []byte("allow_managed_hooks_only = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := enforceCodexUserHookPolicy(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "allow_managed_hooks_only") {
		t.Fatalf("system policy forbids user hooks = %v, want a refusal", err)
	}
}

func closedCodexRPCEvents() <-chan codexRPCEvent {
	events := make(chan codexRPCEvent)
	close(events)
	return events
}
