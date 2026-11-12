// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// setupRefusedBeforeAnyChange reports whether a connector's setup failed
// before it wrote anything: a hook contract or executable admission refusal,
// a version probe that ran out of time, or a Setup that refused unchanged.
// The connector's earlier registration and lock entry are then still the ones
// on disk.
func setupRefusedBeforeAnyChange(err error) bool {
	return errors.Is(err, ErrHookContractAdmission) ||
		errors.Is(err, connector.ErrAgentVersionProbeTimeout) ||
		errors.Is(err, connector.ErrExecutableAdmission) ||
		errors.Is(err, connector.ErrSetupRefusedUnchanged)
}

// connectorRefusedAtCustody reports a refusal made before Setup wrote anything
// because another account can write where the guard of a connector lives: the
// plugin folder chain or file (connector.PluginFolderRefusedBeforeChange), or
// the folder of the agent executable. The user clears it with the command the
// refusal names, so only that connector waits for a restart; failing the start
// for it left every other connector unchecked (GAP-0798).
func connectorRefusedAtCustody(err error) bool {
	return connector.PluginFolderRefusedBeforeChange(err) ||
		errors.Is(err, connector.ErrAgentInstallNotTrusted) && setupRefusedBeforeAnyChange(err)
}

// agentNotInstalledReason skips only a connector with positive absence
// evidence. A missing selected executable at an arbitrary path can mean the
// agent moved, so that case keeps the existing startup refusal.
func agentNotInstalledReason(opts connector.SetupOpts, name string) string {
	if executable := strings.TrimSpace(opts.AgentExecutable); executable != "" {
		if !filepath.IsAbs(executable) {
			return ""
		}
		if _, err := os.Lstat(executable); !errors.Is(err, fs.ErrNotExist) {
			return ""
		}
		if !removedAmpPackagePath(name, executable) {
			return ""
		}
		if agentBinaryMayExistNow(name) {
			return ""
		}
		return fmt.Sprintf("its selected package executable %s is gone and no current agent binary was found", executable)
	}
	// A prior selected path can move outside discovery's finite search
	// locations. Its missing cache entry alone does not prove removal.
	if previous := connector.LoadHookContractLockEntry(opts.DataDir, name); strings.TrimSpace(previous.AgentExecutable) != "" {
		return ""
	}
	if connector.CachedAgentNotFound(opts.DataDir, name) && !agentBinaryMayExistNow(name) {
		return "discovery did not find it and no current agent binary was found"
	}
	return ""
}

// removedAmpPackagePath recognizes the native image of an Amp npm package,
// rather than treating an arbitrary selected path as proof of removal.
func removedAmpPackagePath(name, executable string) bool {
	if runtime.GOOS != "windows" || name != "amp" {
		return false
	}
	roaming := strings.TrimSpace(os.Getenv("APPDATA"))
	if !filepath.IsAbs(roaming) {
		return false
	}
	for _, relative := range [][]string{
		{"npm", "node_modules", "@ampcode", "cli"},
		{"npm", "node_modules", "@sourcegraph", "amp", "node_modules", "@ampcode", "cli"},
	} {
		packageDir := filepath.Join(append([]string{roaming}, relative...)...)
		if !strings.EqualFold(filepath.Clean(executable), filepath.Join(packageDir, "bin", "amp.exe")) {
			continue
		}
		_, err := os.Lstat(packageDir)
		return errors.Is(err, fs.ErrNotExist)
	}
	return false
}

// agentBinaryMayExistNow checks the catalog's binary names on PATH and in
// common per-user and system bins. An unreadable path, unknown signature, or
// lookup error keeps the existing startup refusal.
func agentBinaryMayExistNow(name string) bool {
	signatures, err := inventory.LoadAISignatures()
	if err != nil {
		return true
	}
	var names []string
	for _, signature := range signatures {
		if signature.SupportedConnector == name {
			names = append(names, signature.BinaryNames...)
		}
	}
	if len(names) == 0 {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return true
	}
	// Claude Desktop runs Claude Cowork with the Claude Code engine it keeps
	// in its data folder, and that engine runs the claudecode hooks: an
	// account with Claude Desktop and no claude CLI still has the agent.
	if name == "claudecode" && claudeDesktopEngineMayExist(home) {
		return true
	}
	dirs := []string{filepath.Join(home, ".local", "bin"), filepath.Join(home, "bin")}
	switch runtime.GOOS {
	case "linux":
		dirs = append(dirs, "/usr/local/bin", "/usr/bin", "/bin", "/opt/dc-agents/bin")
	case "darwin":
		dirs = append(dirs, "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin", "/opt/dc-agents/bin")
	case "windows":
		dirs = append(dirs, filepath.Join(home, "scoop", "shims"))
		roaming, local := os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA")
		if roaming == "" || local == "" {
			return true
		}
		dirs = append(dirs,
			filepath.Join(roaming, "npm"), filepath.Join(local, "pnpm"),
			filepath.Join(local, "Microsoft", "WinGet", "Links"),
			filepath.Join(local, "Programs", "OpenAI", "Codex", "bin"),
			filepath.Join(local, "OpenAI", "Codex", "bin"),
			filepath.Join(local, "hermes", "hermes-agent", "venv", "Scripts"),
			filepath.Join(local, "hermes", "bin"),
		)
		for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
			if root != "" {
				dirs = append(dirs, filepath.Join(root, "nodejs"), filepath.Join(root, "OpenAI", "Codex", "bin"))
			}
		}
	}
	for _, binary := range names {
		if binary == "" || binary != filepath.Base(binary) {
			return true
		}
		if found, err := exec.LookPath(binary); err == nil {
			if !staleAmpNPMLauncher(name, found) {
				return true
			}
		} else if !errors.Is(err, exec.ErrNotFound) {
			return true
		}
		variants := []string{binary}
		if runtime.GOOS == "windows" {
			variants = []string{binary + ".exe", binary + ".cmd", binary + ".bat", binary + ".com"}
		}
		for _, dir := range dirs {
			for _, variant := range variants {
				path := filepath.Join(dir, variant)
				if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) && !staleAmpNPMLauncher(name, path) {
					return true
				}
			}
		}
	}
	if runtime.GOOS == "windows" {
		// npm can leave a native image in its package tree even when its
		// PATH shim is absent. These are the exact Amp package locations
		// accepted by setup's native-image selection.
		if name == "amp" {
			roaming := os.Getenv("APPDATA")
			if roaming == "" {
				return true
			}
			for _, relative := range [][]string{
				{"npm", "node_modules", "@ampcode", "cli", "bin", "amp.exe"},
				{"npm", "node_modules", "@sourcegraph", "amp", "node_modules", "@ampcode", "cli", "bin", "amp.exe"},
			} {
				if _, err := os.Lstat(filepath.Join(append([]string{roaming}, relative...)...)); !errors.Is(err, fs.ErrNotExist) {
					return true
				}
			}
		}
	}
	return false
}

// staleAmpNPMLauncher recognizes an npm launcher left in the account's bin
// folder after its package directory was removed. It is not a native Amp
// image. Any unknown or changed launcher remains evidence of a possible
// installation, so setup keeps its existing refusal in that case.
func staleAmpNPMLauncher(name, path string) bool {
	if name != "amp" || runtime.GOOS != "windows" {
		return false
	}
	return staleAmpNPMLauncherAt(path, os.Getenv("APPDATA"))
}

func staleAmpNPMLauncherAt(path, appData string) bool {
	roaming := strings.TrimSpace(appData)
	npmDir := filepath.Join(roaming, "npm")
	if !filepath.IsAbs(roaming) || !strings.EqualFold(filepath.Clean(filepath.Dir(path)), npmDir) ||
		!strings.EqualFold(filepath.Base(path), "amp.cmd") {
		return false
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 16*1024 {
		return false
	}
	body, err := os.ReadFile(path)
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(before, after) ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return false
	}
	target := ampNPMLauncherTarget(string(body))
	if target == "" || pathpkg.Clean(target) != target {
		return false
	}
	for _, relative := range [][]string{
		{"node_modules", "@sourcegraph", "amp", "node_modules", "@ampcode", "cli"},
		{"node_modules", "@sourcegraph", "amp"},
		{"node_modules", "@ampcode", "cli"},
	} {
		marker := strings.Join(relative, "/")
		if !strings.HasPrefix(target, marker+"/") {
			continue
		}
		_, err := os.Lstat(filepath.Join(append([]string{npmDir}, relative...)...))
		return errors.Is(err, fs.ErrNotExist)
	}
	return false
}

// ampNPMLauncherTarget accepts only a direct npm target or the command line
// emitted by npm's cmd shim. Other active lines could select another image.
func ampNPMLauncherTarget(body string) string {
	var target string
	for _, raw := range strings.Split(body, "\n") {
		line := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/"))
		comment := (strings.HasPrefix(line, "rem ") || strings.HasPrefix(line, "::")) &&
			!strings.ContainsAny(line, "&|<>")
		if line == "" || comment ||
			ampNPMLauncherScaffold(line) {
			continue
		}
		invoked := ampNPMInvokedTarget(line)
		if invoked == "" || target != "" {
			return ""
		}
		target = invoked
	}
	return target
}

func ampNPMLauncherScaffold(line string) bool {
	switch line {
	case "@echo off", "goto start", ":find_dp0", "set dp0=%~dp0", "exit /b", ":start",
		"setlocal", "call :find_dp0", "if exist \"%dp0%/node.exe\" (",
		"set \"_prog=%dp0%/node.exe\"", ") else (", "set \"_prog=node\"",
		"set pathext=%pathext:;.js;=;%", ")":
		return true
	}
	return false
}

func ampNPMInvokedTarget(line string) string {
	if !strings.HasSuffix(line, "%*") {
		return ""
	}
	command := strings.TrimSpace(strings.TrimSuffix(line, "%*"))
	command = strings.TrimPrefix(command, "endlocal & goto #_undefined_# 2>nul || title %comspec% & ")
	if strings.HasPrefix(command, "\"%_prog%\" ") {
		command = strings.TrimSpace(strings.TrimPrefix(command, "\"%_prog%\" "))
	}
	command = strings.Trim(command, "\"")
	for _, prefix := range []string{"%~dp0/", "%dp0%/"} {
		if strings.HasPrefix(command, prefix) && !strings.ContainsAny(command, " \t\"&|<>") {
			return strings.TrimPrefix(command, prefix)
		}
	}
	return ""
}

// agentNotInstalledRefusal is the health reason of a connector skipped because
// its agent is not installed. It names the two fixes; the cause is in the
// gateway log.
func agentNotInstalledRefusal(name, why string) string {
	return fmt.Sprintf("the agent is not installed for this account (%s); reinstall it and run: defenseclaw-gateway restart, or remove the connector: defenseclaw setup remove %s", why, name)
}

// openCodeV2RequiredRefusal is the health reason of an OpenCode connector
// skipped because the OpenCode the gateway found is not V2. The version is in
// the gateway log.
func openCodeV2RequiredRefusal(name string) string {
	return fmt.Sprintf("the OpenCode the gateway found for this account is not V2, and V2 is required; put OpenCode V2 first on the PATH of the shell that starts the gateway and run: defenseclaw-gateway restart, or remove the connector: defenseclaw setup remove %s", name)
}

// claudeDesktopEngineMayExist reports a Claude Desktop engine folder
// (<data>/claude-code, for every deployment and install of this account:
// internal/claudedesktop) that holds at least one entry. An unreadable
// folder, or a data folder glob that left folders out, counts as present:
// only positive absence lets the gateway skip the connector.
func claudeDesktopEngineMayExist(home string) bool {
	dirs, overflow := claudedesktop.EngineDirs(runtime.GOOS, claudedesktop.FoldersFromEnv(runtime.GOOS, home, os.Getenv))
	if overflow {
		return true
	}
	for _, engine := range dirs {
		f, err := os.Open(engine.Path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return true
			}
			continue
		}
		entries, readErr := f.ReadDir(1)
		_ = f.Close()
		if len(entries) > 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
			return true
		}
	}
	return false
}
