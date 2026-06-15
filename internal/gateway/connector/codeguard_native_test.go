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

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexCodeGuardSkillInstallCopiesSoftwareSecurity(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "project-codeguard")
	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardCodexSkillName)
	writeTestFile(t, filepath.Join(sourceDir, "SKILL.md"), `---
name: software-security
---

# Software Security Skill (Project CodeGuard)
`)
	writeTestFile(t, filepath.Join(sourceDir, "rules", "codeguard-1-hardcoded-credentials.md"), "# Rule\n")

	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = repoDir
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	codexHome := filepath.Join(dir, "codex-home")
	t.Setenv("CODEX_HOME", codexHome)

	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	if err := ensureCodexCodeGuardSkill(context.Background(), opts); err != nil {
		t.Fatalf("ensureCodexCodeGuardSkill: %v", err)
	}

	targetDir := filepath.Join(codexHome, "skills", nativeCodeGuardCodexSkillName)
	if data, err := os.ReadFile(filepath.Join(targetDir, "SKILL.md")); err != nil {
		t.Fatalf("read installed SKILL.md: %v", err)
	} else if !strings.Contains(string(data), "Project CodeGuard") {
		t.Fatalf("installed SKILL.md does not contain Project CodeGuard marker:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "rules", "codeguard-1-hardcoded-credentials.md")); err != nil {
		t.Fatalf("rule file was not copied: %v", err)
	}
}

func TestCodexCodeGuardSkillInstallRefusesExistingUnrelatedSkill(t *testing.T) {
	dir := t.TempDir()
	codexHome := filepath.Join(dir, "codex-home")
	t.Setenv("CODEX_HOME", codexHome)

	targetSkill := filepath.Join(codexHome, "skills", nativeCodeGuardCodexSkillName, "SKILL.md")
	writeTestFile(t, targetSkill, `---
name: software-security
---

# User-owned skill
`)

	err := ensureCodexCodeGuardSkill(context.Background(), SetupOpts{DataDir: filepath.Join(dir, "data")})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("ensureCodexCodeGuardSkill error = %v, want refusing to overwrite", err)
	}
	if data, err := os.ReadFile(targetSkill); err != nil {
		t.Fatalf("read target skill: %v", err)
	} else if strings.Contains(string(data), "Project CodeGuard") {
		t.Fatalf("installer overwrote user-owned skill:\n%s", data)
	}
}

func TestClaudeCodeCodeGuardPluginInstallRunsMarketplaceAndPluginCommands(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "claude.log")
	installFakeClaude(t, dir)
	t.Setenv("DEFENSECLAW_FAKE_CLAUDE_LOG", logPath)

	if err := ensureClaudeCodeCodeGuardPlugin(context.Background()); err != nil {
		t.Fatalf("ensureClaudeCodeCodeGuardPlugin: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake claude log: %v", err)
	}
	got := string(logData)
	for _, want := range []string{
		"plugin list",
		"plugin marketplace add " + nativeCodeGuardClaudeMarketplace,
		"plugin install --scope user " + nativeCodeGuardClaudePlugin,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("fake claude log missing %q:\n%s", want, got)
		}
	}
}

func TestClaudeCodeCodeGuardPluginInstallSkipsWhenAlreadyInstalled(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "claude.log")
	installFakeClaude(t, dir)
	t.Setenv("DEFENSECLAW_FAKE_CLAUDE_LOG", logPath)
	t.Setenv("DEFENSECLAW_FAKE_CLAUDE_LIST", nativeCodeGuardClaudePlugin)

	if err := ensureClaudeCodeCodeGuardPlugin(context.Background()); err != nil {
		t.Fatalf("ensureClaudeCodeCodeGuardPlugin: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake claude log: %v", err)
	}
	got := strings.TrimSpace(string(logData))
	if got != "plugin list" {
		t.Fatalf("fake claude log = %q, want only plugin list", got)
	}
}

func installFakeClaude(t *testing.T, dir string) {
	t.Helper()
	binDir := filepath.Join(dir, "bin")
	script := filepath.Join(binDir, "claude")
	writeTestFile(t, script, `#!/bin/sh
printf '%s\n' "$*" >> "$DEFENSECLAW_FAKE_CLAUDE_LOG"
if [ "$1" = "plugin" ] && [ "$2" = "list" ]; then
  if [ -n "$DEFENSECLAW_FAKE_CLAUDE_LIST" ]; then
    printf '%s\n' "$DEFENSECLAW_FAKE_CLAUDE_LIST"
  fi
  exit 0
fi
exit 0
`)
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatalf("chmod fake claude: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
