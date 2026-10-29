// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const codeManagedLaunchUninspected = "managed_launch_uninspected"
const codeManagedLaunchAuditUnavailable = "managed_launch_audit_unavailable"

func pluginLaunchConnectorName(name string) string {
	if name == "kiro-cli" {
		return "kiro"
	}
	if name == "agy" {
		return "antigravity"
	}
	if name == "claude" {
		return "claudecode"
	}
	return name
}

// describePluginLaunchCoverage checks running processes independently of the
// plugins: a plugin that was skipped cannot tell the gateway it was skipped.
// An enrolled account's uninspected or unprovable launch makes host coverage
// incomplete until that process ends, even while the managed hook files
// remain installed. The launches of an account the deployment does not
// enroll (launchEnrollment) are not judged or audited.
func (l *lifecycle) describePluginLaunchCoverage(ctx context.Context, record *Deployment) {
	if record == nil || record.NoStart || (l.opts.Action != ActionStatus && l.opts.Action != ActionVerify) {
		return
	}
	env, result := l.env, l.result
	if env.Geteuid == nil || env.Geteuid() != 0 {
		return // the lifecycle already refuses an unprivileged verification
	}
	raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		return // the config check reports this separately
	}
	cfg, err := env.loadConfigCandidate(raw)
	if err != nil || cfg == nil {
		return
	}
	enabled := map[string]bool{}
	for _, name := range enterprisehooks.EffectiveUnixHookConnectors(cfg, connector.NewDefaultRegistry()) {
		enabled[name] = true
	}
	if !enabled["claudecode"] && !enabled["opencode"] && !enabled["amp"] && !enabled["kiro"] &&
		!enabled["devin"] && !enabled["hermes"] && !enabled["antigravity"] {
		return
	}
	var sessions []agentSession
	switch env.GOOS {
	case "linux":
		sessions, err = env.linuxAgentSessionsWithError()
	case "darwin":
		sessions, err = env.darwinAgentSessionsWithError(ctx)
	default:
		return
	}
	if err != nil {
		message := "could not inspect running agent launches: " + err.Error()
		result.AddWarning("managed_launch_scan_unknown", message)
		result.MarkCoverageIncomplete("managed_launch_scan_unknown")
		if l.opts.Action == ActionVerify {
			result.AddError("managed_launch_scan_unknown", message)
		}
		return
	}
	claudeParents := map[int]bool{}
	for _, session := range sessions {
		if session.Agent == "claude" && session.PPID > 0 {
			claudeParents[session.PPID] = true
		}
	}
	enrolled := env.launchEnrollment(cfg)
	for _, session := range sessions {
		name := pluginLaunchConnectorName(session.Agent)
		if session.UID == 0 || session.UID == record.ServiceUID || !enabled[name] ||
			(!pluginLaunchConnector(session.Agent) && session.Agent != "claude") {
			continue
		}
		if name == "claudecode" && claudeLaunchShim(session, claudeParents) {
			continue // its Claude Code child is checked as a session of its own
		}
		if !enrolled.covers(session.UID, func() (string, string) { return env.pluginLaunchAccount(ctx, session.UID) }) {
			continue // excluded, exempt or not admitted: DefenseClaw does not protect this account
		}
		l.describePluginLaunchSession(ctx, session, name)
	}
}

func (l *lifecycle) describePluginLaunchSession(ctx context.Context, session agentSession, name string) {
	env, result := l.env, l.result
	who, home := env.pluginLaunchAccount(ctx, session.UID)
	reason := ""
	if name == "claudecode" {
		reason = claudeManagedLaunchCoverage(session.Args, session.Executable)
	} else {
		reason = enterprisestatus.PluginLaunchCoverage(name, session.Args, session.Env, session.EnvKnown, home)
	}
	if reason == "" && !session.ArgsKnown {
		reason = "launch_arguments_unverified"
	}
	if reason == "" {
		return
	}
	message := fmt.Sprintf("user %s runs %s (pid %d): %s; its managed hook or plugin load is not proven, so tool calls in this session may be uninspected. Close this session and restart without the bypass", who, name, session.PID, launchCoverageExplanation(reason))
	result.AddWarning(codeManagedLaunchUninspected, message)
	result.MarkCoverageIncomplete(codeManagedLaunchUninspected)
	if l.opts.Action == ActionVerify {
		result.AddError(codeManagedLaunchUninspected, message)
	}
	if env.ReportLaunchCoverage != nil {
		report := managed.LaunchCoverageReport{Connector: name, Reason: reason, PID: session.PID,
			UID: session.UID, StartedAt: session.Started.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")}
		if err := env.ReportLaunchCoverage(ctx, report); err != nil {
			result.AddWarning(codeManagedLaunchAuditUnavailable, "could not audit the uninspected "+name+" session (pid "+strconv.Itoa(session.PID)+"): "+err.Error())
			result.MarkSecurityIncomplete(codeManagedLaunchAuditUnavailable)
		}
	}
}

// pluginLaunchAccount uses the host account database for the account whose
// running process was observed. Release Linux binaries have no cgo, so their
// os/user lookup cannot see SSSD and other NSS directory accounts.
func (env *Env) pluginLaunchAccount(ctx context.Context, uid int) (string, string) {
	id := strconv.Itoa(uid)
	if env.GOOS == "linux" {
		result, err := env.Runner.Run(ctx, "getent", "passwd", id)
		if err == nil {
			fields := strings.Split(strings.TrimSpace(string(result.Stdout)), ":")
			if len(fields) >= 7 && fields[2] == id && plainAccountName(fields[0]) && filepath.IsAbs(fields[5]) {
				return fields[0], filepath.Clean(fields[5])
			}
		}
	}
	if account, err := user.LookupId(id); err == nil && filepath.IsAbs(account.HomeDir) {
		return account.Username, filepath.Clean(account.HomeDir)
	}
	return "uid " + id, ""
}

func launchCoverageExplanation(reason string) string {
	switch reason {
	case "opencode_pure":
		return "OpenCode pure mode skips every managed plugin"
	case "opencode_managed_config_relocated":
		return "OpenCode's managed config directory was relocated"
	case "amp_plugin_config_relocated":
		return "Amp's plugin config directory was relocated"
	case "kiro_hook_config_relocated":
		return "Kiro's hook config directory was relocated"
	case "kiro_alternate_agent":
		return "Kiro selected an agent other than the managed DefenseClaw agent"
	case "kiro_cloud_session":
		return "Kiro selected a cloud session outside local managed hooks"
	case "kiro_resume_placement_unverified":
		return "Kiro may resume a cloud session outside local managed hooks; its placement could not be verified"
	case "devin_config_override":
		return "Devin selected another config file"
	case "hermes_safe_mode":
		return "Hermes safe mode skips its user hooks"
	case "hermes_config_relocated":
		return "Hermes loaded config from another home or managed directory"
	case "user_config_relocated":
		return "the user config directory was relocated"
	case "opencode_user_config_relocated":
		return "OpenCode's user config directory was relocated; the per-user plugin may be absent"
	case "launch_arguments_unverified":
		return "the process arguments could not be verified"
	case "claude_npm_launch_unverified":
		return "the running Claude Code npm script has an unsupported or unreadable managed hook contract"
	case "claude_version_unverified":
		return "the running Claude Code build is not identified as a release with a verified managed hook contract (it is older, unrecognized, or was replaced on disk by an update after it started)"
	default:
		return strings.ReplaceAll(reason, "_", " ")
	}
}

// claudeManagedLaunchCoverage names why a running Claude Code process is not
// proven to run a build with a verified managed hook contract, or "" when it
// is. The build is identified from the executable the kernel recorded
// (Linux /proc/<pid>/exe, the macOS exec path), never from the shape of
// argv: the process can rewrite its arguments, and an interactive Claude
// Code session replaces them with the title "claude". Arguments matter only
// when the executable is a script host, to find the script it runs.
func claudeManagedLaunchCoverage(argv []string, executable string) string {
	if len(argv) == 0 {
		return "launch_arguments_unverified"
	}
	exe := claudeRunningExecutable(executable)
	if exe.path == "" {
		if isScriptHost(filepath.Base(argv[0])) {
			return claudeNPMScriptCoverage(argv)
		}
		return "launch_arguments_unverified"
	}
	if isScriptHost(filepath.Base(exe.path)) {
		return claudeNPMScriptCoverage(argv)
	}
	version := claudeExecutableVersion(exe)
	if version == "" || connector.ResolveHookContract("claudecode", version).Status != connector.HookCompatibilityKnown {
		return "claude_version_unverified"
	}
	return ""
}

// claudeNPMScriptCoverage checks a Node-hosted Claude Code. npm's bin/claude
// of a script-era release is a symlink to the package's cli.js: resolve it
// and inspect the package the process actually launched. When the title
// hides the script, nothing proves which copy runs; every release at or
// above the hook contract floor installs a native binary from npm instead
// (bin/claude.exe), so a hidden-script Node launch is never a supported one.
func claudeNPMScriptCoverage(argv []string) string {
	if len(argv) > 1 && isScriptHost(filepath.Base(argv[0])) && agentCLIOf(argv) == "claude" {
		script := ""
		for _, argument := range argv[1:] {
			if !strings.HasPrefix(argument, "-") {
				script = argument
				break
			}
		}
		if version := claudeNPMScriptVersion(script); version != "" &&
			connector.ResolveHookContract("claudecode", version).Status == connector.HookCompatibilityKnown {
			return ""
		}
	}
	return "claude_npm_launch_unverified"
}

// claudeExecutable is the executable of a running Claude Code process.
type claudeExecutable struct {
	path string
	// replaced: the file at path is gone or is no longer the one the process
	// runs (Linux "(deleted)", a link that no longer resolves). Metadata
	// next to it then describes another build.
	replaced bool
}

// claudeLaunchShims start the Claude Code they select as a child process and
// stay resident under the name "claude": Volta's shim waits on the child's
// exit status. The shim loads no hooks itself; its child is inspected as a
// session of its own.
var claudeLaunchShims = map[string]bool{"volta-shim": true}

// claudeRunningExecutable resolves the kernel's executable path. The macOS
// session scan replaces a relative exec path (a launch as ./claude) with the
// kernel's absolute path of the running image (absoluteExecPath); one that
// stays relative is unknown.
func claudeRunningExecutable(executable string) claudeExecutable {
	path, replaced := strings.CutSuffix(strings.TrimSpace(executable), " (deleted)")
	if path == "" || !filepath.IsAbs(path) {
		return claudeExecutable{}
	}
	path = filepath.Clean(path)
	if replaced {
		return claudeExecutable{path: path, replaced: true}
	}
	// macOS records the path given to execve, before links: npm's and the
	// native installer's bin/claude are links to the build they select.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return claudeExecutable{path: path, replaced: true}
	}
	return claudeExecutable{path: resolved}
}

// claudeExecutableVersion reads the release of a Claude Code build from the
// install layouts that name it: the native installer's versions directory,
// a Homebrew cask's version directory, and the package metadata of npm's
// native binary (bin/claude.exe of @anthropic-ai/claude-code, or the
// platform package that the npm fallback wrapper starts). Anything else, a
// copied, renamed or self-built binary, is not identified.
func claudeExecutableVersion(exe claudeExecutable) string {
	path, name, dir := exe.path, filepath.Base(exe.path), filepath.Dir(exe.path)
	const nativeVersions = "/.local/share/claude/versions/"
	if before, version, ok := strings.Cut(path, nativeVersions); ok && before != "" && version != "" && !strings.Contains(version, "/") {
		return version
	}
	if name == "claude" && filepath.Base(filepath.Dir(filepath.Dir(dir))) == "Caskroom" &&
		strings.HasPrefix(filepath.Base(filepath.Dir(dir)), "claude-code") {
		return filepath.Base(dir)
	}
	if exe.replaced {
		return "" // the package metadata now describes the replacement
	}
	if name == "claude.exe" && filepath.Base(dir) == "bin" {
		if packageDir := filepath.Dir(dir); filepath.Base(packageDir) == "claude-code" && filepath.Base(filepath.Dir(packageDir)) == "@anthropic-ai" {
			return claudePackageVersion(packageDir, "@anthropic-ai/claude-code")
		}
	}
	if name == "claude" && filepath.Base(filepath.Dir(dir)) == "@anthropic-ai" && strings.HasPrefix(filepath.Base(dir), "claude-code-") {
		return claudePackageVersion(dir, "@anthropic-ai/"+filepath.Base(dir))
	}
	return ""
}

// claudeLaunchShim reports a resident launcher shim (claudeLaunchShims) whose
// Claude Code child is running. A shim with no such child stays unverified.
func claudeLaunchShim(session agentSession, claudeParents map[int]bool) bool {
	exe := claudeRunningExecutable(session.Executable)
	return exe.path != "" && !exe.replaced && claudeLaunchShims[filepath.Base(exe.path)] && claudeParents[session.PID]
}

func claudeNPMScriptVersion(script string) string {
	if !filepath.IsAbs(script) {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(script)
	if err != nil || filepath.Base(resolved) != "cli.js" {
		return ""
	}
	packageDir := filepath.Dir(resolved)
	if filepath.Base(packageDir) != "claude-code" || filepath.Base(filepath.Dir(packageDir)) != "@anthropic-ai" {
		return ""
	}
	return claudePackageVersion(packageDir, "@anthropic-ai/claude-code")
}

// claudePackageVersion reads the version of the npm package in packageDir
// when its package.json names want.
func claudePackageVersion(packageDir, want string) string {
	path := filepath.Join(packageDir, "package.json")
	// This metadata is user-controlled. Nonblocking, no-follow opening keeps
	// a FIFO or replaced symlink from stalling privileged status and verify.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	const maxPackageBytes = 64 << 10
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPackageBytes {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPackageBytes+1))
	if err != nil || len(data) > maxPackageBytes {
		return ""
	}
	var metadata struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &metadata) != nil || metadata.Name != want {
		return ""
	}
	return metadata.Version
}
