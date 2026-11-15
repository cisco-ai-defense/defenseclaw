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

// The evidence check that runs when the hook contract lock is published comes
// after Setup wrote the agent files, so its mismatch is not scoped to "refused
// before any change": the start must roll that connector back (T-UPGRADE
// review F1, rel-1-0-10:GAP-0249).
func TestContractPublicationEvidenceMismatchIsNotARefusalBeforeAnyChange(t *testing.T) {
	for _, changed := range []error{errAmpExecutableChanged, errHermesExecutableChanged, errOpenCodeExecutableChanged} {
		inner := fmt.Errorf("selected executable digest does not match protected evidence (%w)", changed)
		if !errors.Is(inner, ErrExecutableAdmission) || !AgentExecutableChangedBeforeChange(inner) {
			t.Fatalf("the admission refusal itself must stay scoped: %v", inner)
		}
		published := contractPublicationEvidenceError("Hermes", inner)
		if errors.Is(published, ErrExecutableAdmission) || errors.Is(published, ErrAgentExecutableChanged) || AgentExecutableChangedBeforeChange(published) {
			t.Fatalf("a publication mismatch reads as a refusal before any change: %v", published)
		}
		if !strings.Contains(published.Error(), "run: defenseclaw setup") {
			t.Fatalf("the publication error lost the setup step: %v", published)
		}
	}
}
