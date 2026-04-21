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
	// Minimal valid bundle: need data.json for loadStore + one good rego, then break eval path via empty store
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"config":{"allow_list_bypass_scan":true,"scan_on_install":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "admission.rego")
	if err := os.WriteFile(good, []byte(`package defenseclaw.admission
import rego.v1
default verdict := "scan"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	eng.SetOTelProvider(nil)

	bad := filepath.Join(dir, "bad.rego")
	if err := os.WriteFile(bad, []byte(`package x
this is not valid rego v1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// readModules will parse-fail on bad.rego, quarantine it, return error → Evaluate emits deny-default
	out, err := eng.Evaluate(context.Background(), AdmissionInput{TargetType: "skill", TargetName: "n", Path: "/x"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Verdict != "rejected" {
		t.Fatalf("verdict=%q", out.Verdict)
	}
	if _, err := os.Stat(bad); err == nil {
		t.Fatal("bad.rego should be quarantined / removed from main dir")
	}
}
