// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

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
// An uninspected or unprovable launch makes host coverage incomplete until
// that process ends, even while the managed hook files remain installed.
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
		result.CoverageComplete, result.SecurityComplete = false, false
		if l.opts.Action == ActionVerify {
			result.AddError("managed_launch_scan_unknown", message)
		}
		return
	}
	for _, session := range sessions {
		name := pluginLaunchConnectorName(session.Agent)
		if session.UID == 0 || session.UID == record.ServiceUID || !enabled[name] ||
			(!pluginLaunchConnector(session.Agent) && session.Agent != "claude") {
			continue
		}
		l.describePluginLaunchSession(ctx, session, name)
	}
}

func (l *lifecycle) describePluginLaunchSession(ctx context.Context, session agentSession, name string) {
	env, result := l.env, l.result
	who, home := env.pluginLaunchAccount(ctx, session.UID)
	reason := ""
	if name == "claudecode" {
		reason = claudeManagedLaunchCoverage(session.Args)
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
	result.CoverageComplete, result.SecurityComplete = false, false
	if l.opts.Action == ActionVerify {
		result.AddError(codeManagedLaunchUninspected, message)
	}
	if env.ReportLaunchCoverage != nil {
		report := managed.LaunchCoverageReport{Connector: name, Reason: reason, PID: session.PID,
			UID: session.UID, StartedAt: session.Started.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")}
		if err := env.ReportLaunchCoverage(ctx, report); err != nil {
			result.AddWarning(codeManagedLaunchAuditUnavailable, "could not audit the uninspected "+name+" session (pid "+strconv.Itoa(session.PID)+"): "+err.Error())
			result.SecurityComplete = false
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
		return "a Claude Code npm script can be a separate copy whose managed hook contract cannot be verified from its process arguments"
	case "claude_version_unverified":
		return "the running Claude Code release has no verified managed hook contract"
	default:
		return strings.ReplaceAll(reason, "_", " ")
	}
}

func claudeManagedLaunchCoverage(argv []string) string {
	if len(argv) == 0 {
		return "launch_arguments_unverified"
	}
	if isScriptHost(filepath.Base(argv[0])) && len(argv) > 1 && agentCLIOf(argv) == "claude" {
		return "claude_npm_launch_unverified"
	}
	const nativeVersions = "/.local/share/claude/versions/"
	if before, version, ok := strings.Cut(argv[0], nativeVersions); ok && before != "" && version != "" {
		version = strings.SplitN(version, "/", 2)[0]
		if connector.ResolveHookContract("claudecode", version).Status != connector.HookCompatibilityKnown {
			return "claude_version_unverified"
		}
	}
	return ""
}
