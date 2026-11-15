// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// GAP-0249: the changed-executable refusal of every connector with executable
// admission is found through its wrappers, is an executable admission, and
// names the setup step; joined with another failure it is not the refusal
// alone.
func TestAgentExecutableChangedRefusalIsScopedAndNamesTheStep(t *testing.T) {
	for _, tc := range []struct {
		changed error
		step    string
	}{
		{ErrCodexExecutableChanged, "run: defenseclaw setup codex --yes"},
		{errAmpExecutableChanged, "run: defenseclaw setup amp --yes"},
		{errHermesExecutableChanged, "run: defenseclaw setup hermes --yes"},
		{errOpenCodeExecutableChanged, "run: defenseclaw setup opencode --yes"},
	} {
		wrapped := fmt.Errorf("connector x setup failed: %w", executableAdmissionRefused(
			fmt.Errorf("executable admission: selected executable digest does not match protected evidence (%w)", tc.changed)))
		if !AgentExecutableChangedBeforeChange(wrapped) || !errors.Is(wrapped, ErrExecutableAdmission) ||
			!errors.Is(wrapped, ErrAgentExecutableChanged) || !errors.Is(wrapped, tc.changed) {
			t.Fatalf("%v: not found as a changed-executable admission refusal", wrapped)
		}
		if !strings.Contains(wrapped.Error(), tc.step) {
			t.Fatalf("%v: does not name %q", wrapped, tc.step)
		}
		if joined := errors.Join(errors.New("restore hooks"), wrapped); AgentExecutableChangedBeforeChange(joined) {
			t.Fatalf("%v: a refusal joined with a failed rollback counted as the refusal alone", joined)
		}
	}
	for _, other := range []error{
		nil,
		executableAdmissionRefused(errors.New("selected executable path does not match protected evidence")),
		agentInstallNotTrusted(errors.New("validate selected executable custody")),
	} {
		if AgentExecutableChangedBeforeChange(other) {
			t.Fatalf("%v: counted as a changed executable", other)
		}
	}
}
