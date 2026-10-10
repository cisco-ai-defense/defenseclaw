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

package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

func TestSkillEnforcerQuarantineAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	quarantineDir := filepath.Join(tmpDir, "quarantine")
	skillDir := filepath.Join(tmpDir, "test-skill")

	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "main.py"), []byte("print('hello')"), 0o644); err != nil {
		t.Fatal(err)
	}

	se := enforce.NewSkillEnforcer(quarantineDir)

	dest, err := se.Quarantine(skillDir)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if _, err := os.Stat(skillDir); !os.IsNotExist(err) {
		t.Fatal("expected original skill directory to be removed after quarantine")
	}

	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("expected quarantine destination to exist: %v", err)
	}

	if !se.IsQuarantined("test-skill") {
		t.Fatal("expected IsQuarantined to return true")
	}

	if err := se.Restore("test-skill", skillDir); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	restoredFile := filepath.Join(skillDir, "main.py")
	data, err := os.ReadFile(restoredFile)
	if err != nil {
		t.Fatalf("expected restored file: %v", err)
	}
	if string(data) != "print('hello')" {
		t.Fatalf("restored content mismatch: %q", string(data))
	}
}
