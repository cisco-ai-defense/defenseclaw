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
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestNativeCodeGuardSourceIsPinnedToCommit(t *testing.T) {
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(nativeCodeGuardRepoCommit) {
		t.Fatalf("nativeCodeGuardRepoCommit = %q, want immutable full commit SHA", nativeCodeGuardRepoCommit)
	}
}

func TestConnectorEnvHomeDirResolvesRelativeOverride(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("CODEX_HOME", "relative-codex-home")

	want := filepath.Join(root, "relative-codex-home")
	if got := codexHomeDir(); got != want {
		t.Fatalf("codexHomeDir() = %q, want %q", got, want)
	}
}

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

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	codexHome := filepath.Join(dir, "codex-home")
	t.Setenv("CODEX_HOME", codexHome)

	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	if err := ensureCodexCodeGuardSkill(context.Background(), opts); err != nil {
		t.Fatalf("ensureCodexCodeGuardSkill: %v", err)
	}

	targetDir := filepath.Join(userHome, ".agents", "skills", nativeCodeGuardCodexSkillName)
	if data, err := os.ReadFile(filepath.Join(targetDir, "SKILL.md")); err != nil {
		t.Fatalf("read installed SKILL.md: %v", err)
	} else if !strings.Contains(string(data), "Project CodeGuard") {
		t.Fatalf("installed SKILL.md does not contain Project CodeGuard marker:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "rules", "codeguard-1-hardcoded-credentials.md")); err != nil {
		t.Fatalf("rule file was not copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(codexHome, "skills", nativeCodeGuardCodexSkillName)); !os.IsNotExist(err) {
		t.Fatalf("CODEX_HOME unexpectedly redirected the personal skill install: %v", err)
	}
	if _, err := os.Stat(codexCodeGuardReceiptPath(opts)); err != nil {
		t.Fatalf("ownership receipt was not published: %v", err)
	}

	if err := teardownCodexCodeGuardSkill(opts); err != nil {
		t.Fatalf("teardownCodexCodeGuardSkill: %v", err)
	}
	for _, removed := range []string{
		targetDir,
		filepath.Join(userHome, ".agents", "skills"),
		filepath.Join(userHome, ".agents"),
		codexCodeGuardReceiptPath(opts),
	} {
		if _, err := os.Lstat(removed); !os.IsNotExist(err) {
			t.Fatalf("owned path survived exact teardown %s: %v", removed, err)
		}
	}
}

func TestCodexCodeGuardSkillInstallRefusesExistingUnrelatedSkill(t *testing.T) {
	dir := t.TempDir()
	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	codexHome := filepath.Join(dir, "codex-home")
	t.Setenv("CODEX_HOME", codexHome)

	targetSkill := filepath.Join(
		userHome,
		".agents",
		"skills",
		nativeCodeGuardCodexSkillName,
		"SKILL.md",
	)
	writeTestFile(t, targetSkill, `---
name: software-security
---

# User-owned skill
`)

	err = ensureCodexCodeGuardSkill(context.Background(), SetupOpts{DataDir: filepath.Join(dir, "data")})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("ensureCodexCodeGuardSkill error = %v, want refusing to overwrite", err)
	}
	if data, err := os.ReadFile(targetSkill); err != nil {
		t.Fatalf("read target skill: %v", err)
	} else if strings.Contains(string(data), "Project CodeGuard") {
		t.Fatalf("installer overwrote user-owned skill:\n%s", data)
	}
}

func TestCodexCodeGuardSkillTeardownPreservesPreexistingInstall(t *testing.T) {
	dir := t.TempDir()
	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)

	targetSkill := filepath.Join(
		userHome,
		".agents",
		"skills",
		nativeCodeGuardCodexSkillName,
		"SKILL.md",
	)
	original := `---
name: software-security
---

# Software Security Skill (Project CodeGuard)
`
	writeTestFile(t, targetSkill, original)
	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	if err := ensureCodexCodeGuardSkill(context.Background(), opts); err != nil {
		t.Fatalf("ensure preexisting Codex CodeGuard skill: %v", err)
	}
	if _, err := os.Lstat(codexCodeGuardReceiptPath(opts)); !os.IsNotExist(err) {
		t.Fatalf("preexisting skill was incorrectly claimed by a receipt: %v", err)
	}
	if err := teardownCodexCodeGuardSkill(opts); err != nil {
		t.Fatalf("teardown preexisting Codex CodeGuard skill: %v", err)
	}
	if data, err := os.ReadFile(targetSkill); err != nil {
		t.Fatalf("preexisting Codex CodeGuard skill was removed: %v", err)
	} else if string(data) != original {
		t.Fatalf("preexisting Codex CodeGuard skill changed:\n%s", data)
	}
}

func TestCodexCodeGuardSkillTeardownPreservesOperatorModifiedOwnedInstall(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "project-codeguard")
	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardCodexSkillName)
	writeTestFile(t, filepath.Join(sourceDir, "SKILL.md"), `---
name: software-security
---

# Software Security Skill (Project CodeGuard)
`)
	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = repoDir
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)

	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	if err := ensureCodexCodeGuardSkill(context.Background(), opts); err != nil {
		t.Fatalf("ensureCodexCodeGuardSkill: %v", err)
	}
	targetSkill := filepath.Join(
		userHome,
		".agents",
		"skills",
		nativeCodeGuardCodexSkillName,
		"SKILL.md",
	)
	file, err := os.OpenFile(targetSkill, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("\n# operator modification\n"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = teardownCodexCodeGuardSkill(opts)
	if err == nil || !strings.Contains(err.Error(), "was modified; preserving it") {
		t.Fatalf("teardown modified owned skill error = %v, want preservation refusal", err)
	}
	if _, err := os.Stat(targetSkill); err != nil {
		t.Fatalf("operator-modified skill was removed: %v", err)
	}
	if _, err := os.Stat(codexCodeGuardReceiptPath(opts)); err != nil {
		t.Fatalf("ownership receipt was removed after drift refusal: %v", err)
	}
}

func TestCodexCodeGuardSkillReceiptFailureRollsBackCopiedTree(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "project-codeguard")
	sourceDir := filepath.Join(repoDir, "skills", nativeCodeGuardCodexSkillName)
	writeTestFile(t, filepath.Join(sourceDir, "SKILL.md"), `---
name: software-security
---

# Software Security Skill (Project CodeGuard)
`)
	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = repoDir
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	oldWriter := nativeCodeGuardCodexReceiptWriter
	nativeCodeGuardCodexReceiptWriter = func(string, codexCodeGuardReceipt) error {
		return errors.New("fixture receipt write failure")
	}
	t.Cleanup(func() { nativeCodeGuardCodexReceiptWriter = oldWriter })

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)

	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	err = ensureCodexCodeGuardSkill(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "fixture receipt write failure") {
		t.Fatalf("receipt failure error = %v, want injected failure", err)
	}
	for _, removed := range []string{
		filepath.Join(userHome, ".agents", "skills", nativeCodeGuardCodexSkillName),
		filepath.Join(userHome, ".agents", "skills"),
		filepath.Join(userHome, ".agents"),
	} {
		if _, err := os.Lstat(removed); !os.IsNotExist(err) {
			t.Fatalf("receipt failure left copied path %s: %v", removed, err)
		}
	}
}

func TestCodexSetupRollsBackRuntimeAfterHookWriterFailure(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Codex managed-hook lifecycle is Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(dir, "defenseclaw")
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	configBefore := []byte("model = \"gpt-5\"\r\n")
	managedBefore := []byte("[operator_policy]\r\nmode = \"strict\"\r\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, managedBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	hookDir := filepath.Join(dataDir, "hooks")
	priorHookPath := filepath.Join(hookDir, "inspect-tool.sh")
	priorHook := []byte("#!/bin/sh\n# preexisting runtime\n")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priorHookPath, priorHook, 0o700); err != nil {
		t.Fatal(err)
	}

	previousConfig := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousConfig })
	previousInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{Source: "focused lifecycle test"}, nil
	}
	t.Cleanup(func() { codexPolicyInspector = previousInspector })
	setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))

	previousWriter := codexWriteHookScriptsForSetup
	codexWriteHookScriptsForSetup = func(hookDir string, opts SetupOpts, connector Connector) error {
		if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, connector); err != nil {
			return err
		}
		return errors.New("fixture hook runtime write failure")
	}
	t.Cleanup(func() { codexWriteHookScriptsForSetup = previousWriter })

	err := NewCodexConnector().Setup(context.Background(), SetupOpts{
		DataDir:        dataDir,
		APIAddr:        "127.0.0.1:18970",
		HookContractID: "codex-hooks-v3",
	})
	if err == nil || !strings.Contains(err.Error(), "fixture hook runtime write failure") {
		t.Fatalf("Setup hook runtime failure = %v, want injected post-write failure", err)
	}
	for path, before := range map[string][]byte{
		configPath:    configBefore,
		managedPath:   managedBefore,
		priorHookPath: priorHook,
	} {
		after, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read rolled-back %s: %v", path, readErr)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("failed repair Setup did not restore %s byte-for-byte\nbefore:\n%s\nafter:\n%s", path, before, after)
		}
	}
	entries, err := os.ReadDir(hookDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(priorHookPath) {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("failed repair Setup changed runtime artifact inventory: %v", names)
	}
	assertCodexFailedSetupBackupsRemoved(t, dataDir)
}

func TestCodexSetupUserConfigFailureRollsBackManagedAndRuntime(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Codex managed-hook lifecycle is Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(dir, "defenseclaw")
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	configBefore := []byte("[features]\r\nhooks = false\r\n")
	managedBefore := []byte("[operator_policy]\r\nmode = \"strict\"\r\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, managedBefore, 0o600); err != nil {
		t.Fatal(err)
	}

	previousConfig := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousConfig })
	previousInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{Source: "focused lifecycle test"}, nil
	}
	t.Cleanup(func() { codexPolicyInspector = previousInspector })
	setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))

	err := NewCodexConnector().Setup(context.Background(), SetupOpts{
		DataDir:        dataDir,
		APIAddr:        "127.0.0.1:18970",
		HookContractID: "codex-hooks-v3",
	})
	if err == nil || !strings.Contains(err.Error(), "Codex hooks are disabled") {
		t.Fatalf("Setup disabled user config error = %v, want config-patch refusal", err)
	}
	assertCodexFailedSetupRestored(t, dataDir, configPath, managedPath, configBefore, managedBefore)
}

func TestCodexSetupRollsBackBothConfigLayersAfterCodeGuardFailure(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("managed Codex hook layer is native-Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(dir, "defenseclaw")
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	configBefore := []byte("model = \"gpt-5\"\r\n")
	managedBefore := []byte("[operator_policy]\r\nmode = \"strict\"\r\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, managedBefore, 0o600); err != nil {
		t.Fatal(err)
	}

	previousConfig := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousConfig })
	previousInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{Source: "focused lifecycle test"}, nil
	}
	t.Cleanup(func() { codexPolicyInspector = previousInspector })
	setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))

	emptyRepo := filepath.Join(dir, "invalid-project-codeguard")
	oldOverride := nativeCodeGuardRepoDirOverride
	nativeCodeGuardRepoDirOverride = emptyRepo
	t.Cleanup(func() { nativeCodeGuardRepoDirOverride = oldOverride })

	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)

	err = NewCodexConnector().Setup(context.Background(), SetupOpts{
		DataDir:          dataDir,
		APIAddr:          "127.0.0.1:18970",
		InstallCodeGuard: true,
		HookContractID:   "codex-hooks-v3",
	})
	if err == nil || !strings.Contains(err.Error(), "CodeGuard skill install") {
		t.Fatalf("Setup CodeGuard failure = %v, want post-patch install failure", err)
	}
	assertCodexFailedSetupRestored(t, dataDir, configPath, managedPath, configBefore, managedBefore)
}

func assertCodexFailedSetupRestored(
	t *testing.T,
	dataDir string,
	configPath string,
	managedPath string,
	configBefore []byte,
	managedBefore []byte,
) {
	t.Helper()
	for path, before := range map[string][]byte{
		configPath:  configBefore,
		managedPath: managedBefore,
	} {
		after, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read rolled-back %s: %v", path, readErr)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("failed Setup did not restore %s byte-for-byte\nbefore:\n%s\nafter:\n%s", path, before, after)
		}
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "hooks")); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(filepath.Join(dataDir, "hooks"))
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("failed fresh Setup left hook scripts or scoped tokens (%v): %v", err, names)
	}
	assertCodexFailedSetupBackupsRemoved(t, dataDir)
}

func assertCodexFailedSetupBackupsRemoved(t *testing.T, dataDir string) {
	t.Helper()
	for _, backupPath := range []string{
		filepath.Join(dataDir, "codex_config_backup.json"),
		managedFileBackupPath(dataDir, "codex", "config.toml"),
		managedFileBackupPath(dataDir, "codex", codexManagedConfigLogicalName),
	} {
		if _, err := os.Lstat(backupPath); !os.IsNotExist(err) {
			t.Fatalf("failed fresh Setup left rollback backup %s: %v", backupPath, err)
		}
	}
}

func TestClaudeCodeCodeGuardPluginInstallRunsMarketplaceAndPluginCommands(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "claude.log")
	claudePath := installFakeClaude(t, dir)
	previousValidator := validateClaudeCodeCodeGuardExecutable
	validateClaudeCodeCodeGuardExecutable = func(SetupOpts) error { return nil }
	t.Cleanup(func() { validateClaudeCodeCodeGuardExecutable = previousValidator })
	t.Setenv("DEFENSECLAW_FAKE_CLAUDE_LOG", logPath)

	if err := ensureClaudeCodeCodeGuardPlugin(context.Background(), SetupOpts{AgentExecutable: claudePath}); err != nil {
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
	claudePath := installFakeClaude(t, dir)
	previousValidator := validateClaudeCodeCodeGuardExecutable
	validateClaudeCodeCodeGuardExecutable = func(SetupOpts) error { return nil }
	t.Cleanup(func() { validateClaudeCodeCodeGuardExecutable = previousValidator })
	t.Setenv("DEFENSECLAW_FAKE_CLAUDE_LOG", logPath)
	t.Setenv("DEFENSECLAW_FAKE_CLAUDE_LIST", nativeCodeGuardClaudePlugin)

	if err := ensureClaudeCodeCodeGuardPlugin(context.Background(), SetupOpts{AgentExecutable: claudePath}); err != nil {
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

func installFakeClaude(t *testing.T, dir string) string {
	t.Helper()
	binDir := filepath.Join(dir, "bin")
	name := "claude"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	source := filepath.Join(binDir, "main.go")
	writeTestFile(t, source, `package main
import ("fmt"; "os"; "strings")
func main() {
  f, err := os.OpenFile(os.Getenv("DEFENSECLAW_FAKE_CLAUDE_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
  if err != nil { panic(err) }
  _, _ = fmt.Fprintln(f, strings.Join(os.Args[1:], " "))
  _ = f.Close()
  if len(os.Args) >= 3 && os.Args[1] == "plugin" && os.Args[2] == "list" { fmt.Println(os.Getenv("DEFENSECLAW_FAKE_CLAUDE_LIST")) }
}
`)
	claudePath := filepath.Join(binDir, name)
	if output, err := exec.Command("go", "build", "-o", claudePath, source).CombinedOutput(); err != nil {
		t.Fatalf("build fake claude: %v\n%s", err, output)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return claudePath
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
