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
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

// GAP-0417: a SKILL.md saved as UTF-16 (Notepad "Unicode", PowerShell 5.1 >)
// was refused by skill-scanner for its NUL bytes and quarantined. The scan
// now reads a copy re-encoded as UTF-8; the skill's own file is unchanged.
func TestUTF16SkillIsScannedFromAUTF8Copy(t *testing.T) {
	skill := filepath.Join(t.TempDir(), "utf16-md")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	text := "---\nname: utf16-md\ndescription: notes\n---\n# Notes\n"
	encoded := []byte{0xFF, 0xFE}
	for _, unit := range utf16.Encode([]rune(text)) {
		encoded = append(encoded, byte(unit), byte(unit>>8))
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "run.py"), []byte("print(1)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, cleanup, err := stageUTF16Skill(skill)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if stage == skill {
		t.Fatal("UTF-16 SKILL.md was not staged")
	}
	if got, _ := os.ReadFile(filepath.Join(stage, "SKILL.md")); string(got) != text {
		t.Fatalf("staged SKILL.md = %q, want the UTF-8 text", got)
	}
	if _, err := os.Stat(filepath.Join(stage, "run.py")); err != nil {
		t.Fatalf("staged copy lacks run.py: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(skill, "SKILL.md")); string(got) != string(encoded) {
		t.Fatal("the skill's own SKILL.md changed")
	}
}
