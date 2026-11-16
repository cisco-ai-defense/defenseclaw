// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
)

// The managed Windows hook enumerator starts an enrolled user's local MCP
// server as that user for the gateway's admission scan (#1164). These are
// the platform-independent checks of that start; the Windows half is in
// mcp_as_user_windows.go.

// mcpAsUserForbiddenFlags turn an allowed launcher into a command runner,
// as the scanner's own launcher check says (cli/defenseclaw/scanner/mcp.py
// _FORBIDDEN_STDIO_FLAGS).
var mcpAsUserForbiddenFlags = map[string]bool{
	"-c": true, "--command": true, "--eval": true, "-e": true, "--exec": true, "--script": true, "-x": true,
}

// mcpAsUserCmdMetacharacters are the characters cmd.exe could reinterpret
// on the npx.cmd hop (_WINDOWS_CMD_METACHARACTERS).
const mcpAsUserCmdMetacharacters = "&|<>()^%!\"\r\n\x00"

// mcpAsUserLauncher is the launcher a published server names: "npx" or
// "uvx", and the file a user's PATH must hold for it.
type mcpAsUserLauncher struct {
	name, file string
}

// checkMCPAsUserDefinition applies the scanner's launcher rules to a
// published server before anything starts: only the bare npx and uvx
// launchers with a package argument, no code-running flag, and nothing
// cmd.exe could reinterpret on the npx.cmd hop. A scan starts the same
// servers as the user that it starts anywhere else.
func checkMCPAsUserDefinition(entry config.MCPServerEntry) (mcpAsUserLauncher, error) {
	if entry.URL != "" || strings.TrimSpace(entry.Command) == "" {
		return mcpAsUserLauncher{}, errors.New("the server is not a local stdio server")
	}
	command := strings.TrimSpace(entry.Command)
	if strings.ContainsAny(command, `/\`) {
		return mcpAsUserLauncher{}, fmt.Errorf("command %q is a path; a scan starts only the bare names npx or uvx", command)
	}
	var launcher mcpAsUserLauncher
	switch strings.ToLower(command) {
	case "npx", "npx.cmd":
		launcher = mcpAsUserLauncher{name: "npx", file: "npx.cmd"}
	case "uvx", "uvx.exe":
		launcher = mcpAsUserLauncher{name: "uvx", file: "uvx.exe"}
	default:
		return mcpAsUserLauncher{}, fmt.Errorf("command %q is not an allowlisted stdio launcher (allowed: npx, uvx)", command)
	}
	packageArg := false
	for _, arg := range entry.Args {
		token := strings.TrimSpace(arg)
		flag := strings.ToLower(strings.SplitN(token, "=", 2)[0])
		if mcpAsUserForbiddenFlags[flag] {
			return mcpAsUserLauncher{}, fmt.Errorf("launcher %q uses forbidden execution flag %q", launcher.name, flag)
		}
		if token != "" && !strings.HasPrefix(token, "-") {
			packageArg = true
		}
		if launcher.name == "npx" && strings.ContainsAny(arg, mcpAsUserCmdMetacharacters) {
			return mcpAsUserLauncher{}, errors.New("an npx argument contains a Windows command metacharacter that cannot be passed safely through npx.cmd")
		}
	}
	if !packageArg {
		return mcpAsUserLauncher{}, fmt.Errorf("launcher %q requires a package/server argument", launcher.name)
	}
	return launcher, nil
}

// findMCPAsUserServer is the published server request names, with the
// definition the gateway scanned.
func findMCPAsUserServer(servers []config.MCPServerEntry, request mcpasuser.Request) (config.MCPServerEntry, error) {
	named := false
	for _, server := range servers {
		if server.Name != request.Name || !sameMCPProject(server.Project, request.Project) {
			continue
		}
		named = true
		if mcpasuser.Digest(server) == request.Digest {
			return server, nil
		}
	}
	if named {
		return config.MCPServerEntry{}, errors.New("the server definition changed after the gateway read it; the gateway scans the new definition at its next poll")
	}
	return config.MCPServerEntry{}, errors.New("the server is not in the MCP servers the hook enumerator published for this user")
}

func sameMCPProject(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// mcpAsUserLauncherFS is the file system view of a launcher lookup, as the
// user sees it.
type mcpAsUserLauncherFS struct {
	// exists reports a file (not a folder) at path.
	exists func(path string) bool
	// trusted fails unless path is a launcher the managed scan trusts:
	// installed for all users in a folder only administrators can change.
	trusted func(path string) error
}

// mcpAsUserLauncherExtensions are the extensions a bare launcher name runs
// with, in the order Windows tries them (the default PATHEXT head), when the
// server's PATHEXT does not name them.
var mcpAsUserLauncherExtensions = []string{".com", ".exe", ".bat", ".cmd"}

// resolveMCPAsUserLauncher is the launcher file the server's agent runs for
// the bare name, looked up as the agent does (the working folder, then PATH,
// with the server's env applied), accepted only when it is the expected
// npx.cmd or uvx.exe and the trust policy of the managed scan accepts it.
// The scanner applies the same policy to a server the gateway starts itself
// (cli/defenseclaw/scanner/mcp.py _resolve_trusted_windows_launcher). A
// different file of the same name earlier in the search (a server PATH entry
// that puts its own npx.cmd first, a .bat beside the real launcher), a
// relative or network PATH entry before it, or an untrusted launcher refuses
// the start, so a definition cannot pick the program that starts before its
// verdict (#1164).
func resolveMCPAsUserLauncher(launcher mcpAsUserLauncher, workDir, pathValue, pathExt string, fs mcpAsUserLauncherFS) (string, error) {
	if fs.exists == nil || fs.trusted == nil {
		return "", errors.New("no launcher check")
	}
	// The extensions in the order the server's PATHEXT tries them, then the
	// defaults it leaves out: an extension that wins for the agent is never
	// skipped here.
	var extensions []string
	for _, ext := range append(strings.Split(pathExt, ";"), mcpAsUserLauncherExtensions...) {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if strings.HasPrefix(ext, ".") && !strings.ContainsAny(ext, `\/`) && !containsFold(extensions, ext) {
			extensions = append(extensions, ext)
		}
	}
	// The working folder is searched first; it was vetted as the user.
	dirs := append([]string{workDir}, strings.Split(pathValue, ";")...)
	for i, dir := range dirs {
		dir = strings.Trim(strings.TrimSpace(dir), `"`)
		if dir == "" {
			continue
		}
		if i > 0 && !mcpAsUserAbsolute(dir) {
			return "", fmt.Errorf("PATH entry %q comes before %s and is not an absolute folder on a local drive", dir, launcher.file)
		}
		base := strings.TrimRight(dir, `\/`) + `\`
		for _, ext := range extensions {
			found := base + launcher.name + ext
			if !fs.exists(found) {
				continue
			}
			if !strings.EqualFold(launcher.name+ext, launcher.file) {
				return "", fmt.Errorf("%s comes before %s in the launcher search, so the agent would not run %s", found, launcher.file, launcher.file)
			}
			if err := fs.trusted(found); err != nil {
				return "", fmt.Errorf("launcher %s is not trusted (%v); on a managed computer a scan starts %s only when it is "+
					"installed for all users under Program Files, in a folder only administrators can change", found, err, launcher.name)
			}
			return found, nil
		}
	}
	return "", fmt.Errorf("%s is not on the PATH the server starts with", launcher.file)
}

func containsFold(values []string, value string) bool {
	for _, v := range values {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

// planMCPAsUserLaunch is the folder and launcher a published server starts
// with, both checked as the user (the caller impersonates the user around
// it): the folder the agent uses (vetClaudeMCPWorkDir, no fallback) and the
// launcher the agent would run there with the server's env. Any refusal
// means no start, so the scan fails and the gateway blocks the server.
func planMCPAsUserLaunch(entry config.MCPServerEntry, home string, otherHomes []string, launcher mcpAsUserLauncher,
	env []string, checks claudeMCPWorkDirChecks, fs mcpAsUserLauncherFS,
) (workDir, launcherPath string, err error) {
	workDir, err = vetClaudeMCPWorkDir(entry, home, otherHomes, checks)
	if err != nil {
		return "", "", fmt.Errorf("MCP server %q is not started in %w", entry.Name, err)
	}
	launcherPath, err = resolveMCPAsUserLauncher(launcher, workDir, mcpAsUserEnvValue(env, "PATH"), mcpAsUserEnvValue(env, "PATHEXT"), fs)
	if err != nil {
		return "", "", fmt.Errorf("MCP server %q is not started: %w", entry.Name, err)
	}
	return workDir, launcherPath, nil
}

// mcpAsUserAbsolute reports a drive-absolute Windows path (C:\...).
func mcpAsUserAbsolute(path string) bool {
	return len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') &&
		(path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z')
}

// mcpAsUserArgv is the command a published server starts as: npx.cmd
// through the system cmd.exe with AutoRun and delayed expansion off, as the
// scanner starts it; uvx.exe directly.
func mcpAsUserArgv(launcher mcpAsUserLauncher, launcherPath, commandProcessor string, args []string) ([]string, error) {
	switch launcher.name {
	case "npx":
		if strings.ContainsAny(launcherPath, mcpAsUserCmdMetacharacters) {
			return nil, errors.New("the npx.cmd path contains a Windows command metacharacter")
		}
		return append([]string{commandProcessor, "/d", "/s", "/v:off", "/c", "call", launcherPath}, args...), nil
	case "uvx":
		return append([]string{launcherPath}, args...), nil
	}
	return nil, fmt.Errorf("launcher %q has no Windows launch plan", launcher.name)
}

// mergeMCPAsUserEnv is the user's own environment with the server's env
// entries on top; Windows names compare without case.
func mergeMCPAsUserEnv(user []string, server map[string]string) []string {
	index := map[string]int{}
	out := make([]string, 0, len(user)+len(server))
	for _, kv := range user {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			// Keep the drive-current-folder entries ("=C:=C:\...").
			out = append(out, kv)
			continue
		}
		index[strings.ToUpper(name)] = len(out)
		out = append(out, kv)
	}
	names := make([]string, 0, len(server))
	for name := range server {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, "=\x00") {
			continue
		}
		kv := name + "=" + server[name]
		if at, ok := index[strings.ToUpper(name)]; ok {
			out[at] = kv
			continue
		}
		index[strings.ToUpper(name)] = len(out)
		out = append(out, kv)
	}
	return out
}

// mcpAsUserEnvValue is the value of name in env.
func mcpAsUserEnvValue(env []string, name string) string {
	for _, kv := range env {
		if key, value, ok := strings.Cut(kv, "="); ok && strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}
