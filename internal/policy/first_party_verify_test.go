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

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0419: the built-in first-party entry codeguard trusted any folder named
// codeguard under ~/.claude/skills, so a skill holding credentials skipped the
// scan by taking the name. Only the shipped CodeGuard skill skips it now.
func TestVerifyFirstPartyTrustsOnlyTheShippedCodeGuard(t *testing.T) {
	shipped := filepath.Join("..", "..", "skills", "codeguard")
	if sig, err := SkillTreeSignature(shipped); err != nil || !codeGuardSkillSignatures[sig] {
		t.Fatalf("skills/codeguard signature %q (err %v) is not pinned in codeGuardSkillSignatures", sig, err)
	}
	install := filepath.Join(t.TempDir(), ".claude", "skills", "codeguard")
	if err := os.MkdirAll(install, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SKILL.md", "skill.yaml", "main.py"} {
		data, err := os.ReadFile(filepath.Join(shipped, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(install, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	verdict := func() string {
		in := AdmissionInput{
			TargetType: "skill", TargetName: "codeguard", Path: install,
			Admission: AdmissionFor(CompileAdmission(nil), "skill"),
		}
		in.VerifyFirstParty()
		return EvaluateAdmissionFallback(in).Verdict
	}
	if got := verdict(); got != "allowed" {
		t.Fatalf("shipped CodeGuard copy: verdict %q, want allowed", got)
	}
	if err := os.WriteFile(filepath.Join(install, "deploy.sh"), []byte("echo deploy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := verdict(); got != "scan" {
		t.Fatalf("folder named codeguard with other content: verdict %q, want scan", got)
	}
}

// An oversized user-controlled file must not consume unbounded time or memory
// while deciding whether a skill is the shipped CodeGuard copy.
func TestSkillTreeSignatureRejectsOversizedFile(t *testing.T) {
	root := t.TempDir()
	file, err := os.Create(filepath.Join(root, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(4<<20 + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := SkillTreeSignature(root); err == nil {
		t.Fatal("oversized skill file was accepted")
	}
}
