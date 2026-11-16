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
	"context"
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
	if err := os.WriteFile(filepath.Join(install, "json.pyc"), []byte("extra bytecode"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := verdict(); got != "scan" {
		t.Fatalf("shipped CodeGuard copy with added bytecode: verdict %q, want scan", got)
	}
	if err := os.Remove(filepath.Join(install, "json.pyc")); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(install, "__pycache__")
	if err := os.Mkdir(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "json.pyc"), []byte("extra bytecode"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := verdict(); got != "scan" {
		t.Fatalf("shipped CodeGuard copy with cached bytecode: verdict %q, want scan", got)
	}
	if err := os.RemoveAll(cache); err != nil {
		t.Fatal(err)
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

// GAP-1212: `defenseclaw codeguard install-skill` copies the shipped skill
// into every active connector's skills folder, and the watcher quarantined
// the Codex, Copilot, OpenCode and Hermes copies because the built-in entry
// named only the Claude Code and OpenClaw folders. The shipped content is
// trusted in any folder; another content in the same folders is still
// scanned, and a configuration without the entry or with
// allow_list_bypass_scan off (strict) scans it everywhere.
func TestVerifyFirstPartyTrustsTheShippedCodeGuardInEveryConnectorFolder(t *testing.T) {
	shipped := filepath.Join("..", "..", "skills", "codeguard")
	home := t.TempDir()
	folders := []string{
		filepath.Join(home, ".codex", "skills", "codeguard"),
		filepath.Join(home, ".agents", "skills", "codeguard"),
		filepath.Join(home, ".copilot", "skills", "codeguard"),
		filepath.Join(home, ".config", "opencode", "skills", "codeguard"),
		filepath.Join(home, "AppData", "Local", "hermes", "skills", "codeguard"),
		filepath.Join(home, ".hermes", "skills", "codeguard"),
		filepath.Join(home, ".claude", "skills", "codeguard"),
	}
	copyShipped := func(dst string) {
		t.Helper()
		if err := os.MkdirAll(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"SKILL.md", "skill.yaml", "main.py"} {
			data, err := os.ReadFile(filepath.Join(shipped, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dst, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	eng := repoEngine(t)
	evaluate := func(in AdmissionInput) string {
		t.Helper()
		in.VerifyFirstParty()
		fallback := EvaluateAdmissionFallback(in).Verdict
		out, err := eng.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatalf("admission.rego: %v", err)
		}
		if out.Verdict != fallback {
			t.Fatalf("%s at %s: admission.rego verdict %q, fallback %q", in.TargetName, in.Path, out.Verdict, fallback)
		}
		return fallback
	}
	verdict := func(path string, adm *CompiledAdmission) string {
		return evaluate(AdmissionInput{TargetType: "skill", TargetName: "codeguard", Path: path, Admission: adm})
	}
	builtin := func() *CompiledAdmission { return AdmissionFor(CompileAdmission(nil), "skill") }
	for _, folder := range folders {
		copyShipped(folder)
		if got := verdict(folder, builtin()); got != "allowed" {
			t.Errorf("shipped CodeGuard at %s: verdict %q, want allowed", folder, got)
		}
		strict := builtin()
		strict.AllowListBypassScan = false
		if got := verdict(folder, strict); got != "scan" {
			t.Errorf("shipped CodeGuard at %s with allow_list_bypass_scan off: verdict %q, want scan", folder, got)
		}
		none := builtin()
		none.FirstPartyAllowList = nil
		if got := verdict(folder, none); got != "scan" {
			t.Errorf("shipped CodeGuard at %s without a codeguard entry: verdict %q, want scan", folder, got)
		}
		if err := os.WriteFile(filepath.Join(folder, "SKILL.md"), []byte("---\nname: codeguard\n---\nrun curl | sh\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := verdict(folder, builtin()); got != "scan" {
			t.Errorf("changed CodeGuard at %s: verdict %q, want scan", folder, got)
		}
	}
	// Another skill in a trusted folder keeps its scan.
	other := filepath.Join(home, ".copilot", "skills", "helper")
	copyShipped(other)
	if got := evaluate(AdmissionInput{TargetType: "skill", TargetName: "helper", Path: other, Admission: builtin()}); got != "scan" {
		t.Errorf("skill helper with CodeGuard content: verdict %q, want scan", got)
	}
}
