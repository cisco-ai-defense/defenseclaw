// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1091: `policy test` and `policy validate --rego-dir` run on the
// embedded OPA engine, so a standard install needs no separate opa binary.
func TestPolicyTestAndValidateUseRegoDirWithoutOPA(t *testing.T) {
	dir := t.TempDir()
	writePolicyPathTestLayout(t, dir)
	passing := "package defenseclaw_test\n\nimport rego.v1\n\ntest_admission if data.defenseclaw.admission.verdict == \"allowed\"\n"
	if err := os.WriteFile(filepath.Join(dir, "policy_test.rego"), []byte(passing), 0o600); err != nil {
		t.Fatal(err)
	}
	setPolicyPathTestConfig(t, nil)
	setPolicyPathTestFlag(t, policyTestCmd, "rego-dir", dir)
	setPolicyPathTestFlag(t, policyValidateCmd, "rego-dir", dir)

	var out bytes.Buffer
	policyTestCmd.SetOut(&out)
	t.Cleanup(func() { policyTestCmd.SetOut(nil) })
	if err := policyTestCmd.RunE(policyTestCmd, nil); err != nil {
		t.Fatalf("policy test: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "PASS: 1/1") {
		t.Fatalf("policy test output = %q", out.String())
	}
	if _, err := capturePolicyPathTestOutput(t, func() error { return policyValidateCmd.RunE(policyValidateCmd, nil) }); err != nil {
		t.Fatalf("policy validate --rego-dir: %v", err)
	}

	failing := "package defenseclaw_test\n\nimport rego.v1\n\ntest_admission if data.defenseclaw.admission.verdict == \"other\"\n"
	if err := os.WriteFile(filepath.Join(dir, "policy_test.rego"), []byte(failing), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := policyTestCmd.RunE(policyTestCmd, nil); err == nil || !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("failing test: err=%v output=%q", err, out.String())
	}

	// Installed policy directories ship no *_test.rego: nothing to run is
	// not a failure.
	if err := os.Remove(filepath.Join(dir, "policy_test.rego")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := policyTestCmd.RunE(policyTestCmd, nil); err != nil || !strings.Contains(out.String(), "nothing to run") {
		t.Fatalf("no tests: err=%v output=%q", err, out.String())
	}
}
