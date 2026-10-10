// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEngine_AdmissionDenyDefault_OnEvalFailure(t *testing.T) {
	dir := t.TempDir()
	// Two complete definitions that disagree: the module compiles, but every
	// evaluation fails with a conflict error.
	module := `package defenseclaw.admission
import rego.v1
verdict := "allowed" if input.target_type
verdict := "clean" if input.target_type
`
	if err := os.WriteFile(filepath.Join(dir, "admission.rego"), []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	out, err := eng.Evaluate(context.Background(), AdmissionInput{TargetType: "skill", TargetName: "n", Path: "/x"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Verdict != "rejected" || out.InstallAction != "block" {
		t.Fatalf("out = %+v, want the fail-closed rejection", out)
	}
}
