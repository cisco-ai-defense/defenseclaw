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

package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodeGuardBuiltinProvenanceIsCodeOwnedAndNotJSON(t *testing.T) {
	rulesDir := t.TempDir()
	custom := `version: 1
rules:
  - id: CG-EXEC-001
    severity: critical
    title: Reused builtin ID
    pattern: CUSTOM_COLLISION
    extensions: [.py]
`
	if err := os.WriteFile(filepath.Join(rulesDir, "custom.yaml"), []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}

	scanner := NewCodeGuardScanner(rulesDir)
	builtin := scanner.ScanContentWithProvenance("app.py", "os.system(cmd)")
	if !builtin.Complete() || len(builtin.Findings()) != 1 || !builtin.Findings()[0].CodeGuardBuiltinMatch("CG-EXEC-001") {
		t.Fatalf("builtin scan = complete:%t findings:%+v", builtin.Complete(), builtin.Findings())
	}
	customScan := scanner.ScanContentWithProvenance("app.py", "CUSTOM_COLLISION")
	if !customScan.Complete() || len(customScan.Findings()) != 1 || customScan.Findings()[0].CodeGuardBuiltinMatch("CG-EXEC-001") {
		t.Fatalf("custom collision acquired builtin provenance: %+v", customScan.Findings())
	}
	mutated := builtin.Findings()[0]
	mutated.ID = "CG-CUSTOM-001"
	mutated.RuleID = "CG-CUSTOM-001"
	if mutated.CodeGuardBuiltinMatch("CG-CUSTOM-001") {
		t.Fatal("builtin provenance was not bound to the exact scanner rule ID")
	}

	wire, err := json.Marshal(builtin.Findings()[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(wire)), "provenance") ||
		strings.Contains(strings.ToLower(string(wire)), "builtin") {
		t.Fatalf("private CodeGuard provenance leaked to JSON: %s", wire)
	}
	var decoded Finding
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CodeGuardBuiltinMatch("CG-EXEC-001") {
		t.Fatal("JSON round trip manufactured CodeGuard builtin provenance")
	}
}
