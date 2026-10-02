// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// hookForeignGuardPayloadLimit bounds how much of the hook payload the
// guard buffers to find the agent's working directory; hookexec still
// applies its own cap to the full stream.
const hookForeignGuardPayloadLimit = 1 << 20

// hookForeignGuardSummaryPath resolves the standalone public machine policy
// summary. It is replaceable in tests. A host without a standalone layout
// (Secure Client, unmanaged) has no summary, and the guard is a no-op.
var hookForeignGuardSummaryPath = func() (string, bool) {
	layout, _, _, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return "", false
	}
	return enterprisepolicy.PublicPolicyPathFor(layout), true
}

var hookForeignGuardLoad = enterprisepolicy.LoadPublicPolicy

// hookForeignGuardRecord records a block for the guardian to report
// (replaceable in tests).
var hookForeignGuardRecord = enterprisepolicy.RecordForeignHookBlock

// hookForeignGuardRecordEnv records the environment redirects the agent
// runs with, for the guardian's cleanup (replaceable in tests).
var hookForeignGuardRecordEnv = enterprisepolicy.RecordEnvRedirect

// hookForeignGuardAgentProcess names the agent process that runs the hook,
// which keeps the hooks it loaded for its lifetime (replaceable in tests).
var hookForeignGuardAgentProcess = agentprocess.Identity

// hookAgentHost names the process that started the agent (replaceable in
// tests).
var hookAgentHost = agentprocess.Host

// hookAgentExecutable is the agent engine's executable path (replaceable
// in tests).
var hookAgentExecutable = agentprocess.Executable

// hookForeignGuardExchange is replaceable in tests. Production reaches the
// standalone gateway over its authenticated hook transport.
var hookForeignGuardExchange = exchangeForeignHookSession

// foreignHookSessionUnavailableReason is the block reason when the gateway
// cannot answer for the agent session's hook record.
const foreignHookSessionUnavailableReason = "enterprise_foreign_hook_blocked: DefenseClaw could not check this agent session's hook record with its gateway, so the call is blocked. Retry when the DefenseClaw gateway is running; if the block continues, restart the agent."

// applyEnterpriseForeignHookGuard denies a hook invocation on a standalone
// managed host while an unapproved hook that could rewrite the tool call
// after DefenseClaw checks it is present in the agent's user or project
// config, and for the rest of an agent session that started while one was
// present (the agent keeps running hooks it loaded when the session
// started). It covers machine-policy (--enterprise-managed) and per-user
// registrations alike. The denial reuses hookexec's managed fail-closed
// path, so each connector gets its native block response carrying the
// reason (file, digest and allowlist key). A stop or session-end event is
// still evaluated and recorded, but hookexec answers it with the connector's
// neutral allow: a block there would keep the agent running, not stop it.
func applyEnterpriseForeignHookGuard(opts *hookexec.Options) {
	startedAt := time.Now()
	if opts.ManagedEnterprise && strings.TrimSpace(opts.ManagedRuntimeFailure) != "" {
		return
	}
	if !foreignHookGuardedEvent(opts.Connector, opts.Event) {
		return
	}
	path, ok := hookForeignGuardSummaryPath()
	if !ok {
		return
	}
	summary, err := hookForeignGuardLoad(path)
	if errors.Is(err, enterprisepolicy.ErrNoPublicPolicy) {
		return
	}
	if err != nil {
		opts.ManagedEnterprise = true
		opts.ManagedRuntimeFailure = "enterprise_machine_policy_summary_untrusted"
		return
	}
	name := strings.ToLower(strings.TrimSpace(opts.Connector))
	// A standalone host: the managed hook tags the audit with the agent's
	// host process, so Devin Local under Devin Desktop is told apart from
	// the Devin CLI. The lookup (a process snapshot on Windows) runs only
	// when its result is used.
	if opts.ManagedEnterprise {
		opts.AgentHost = hookAgentHost()
	}
	// Every hook call names its surface so the gateway can refuse an
	// unverified app or extension under unverified_versions: refuse, next
	// to the same user's enrolled CLI.
	opts.AgentSurface = connector.ClassifyAgentSurface(name, hookAgentExecutable(), os.Getenv)
	policy, ok := summary.Connectors[name]
	if !ok || !policy.Guard {
		return
	}
	// The scan is part of this invocation: hookexec's request budget starts
	// here, and the scan itself stops (failing closed) well inside it, so a
	// slow or flooded tree can never run into the agent's own hook timeout
	// (which Copilot treats as allow).
	opts.StartedAt = startedAt
	deadline := startedAt.Add(hookForeignGuardScanBudget(name, opts.Event))
	facts := captureHookPayloadFacts(opts)
	if hookexec.HookSurfaceAllowed(name, opts.HookSurface) {
		facts.surface = strings.TrimSpace(opts.HookSurface)
	}
	event := strings.TrimSpace(opts.Event)
	if event == "" {
		event = facts.event
	}
	decision, accountHome := evaluateHookForeignGuard(name, summary.HookBinary, policy, facts, event, deadline)
	if decision.Deny {
		if name == "devin" {
			host := opts.AgentHost
			if host == "" {
				host = hookAgentHost()
			}
			decision.Reason = withDesktopRestartNote(name, host, decision.Reason)
		}
		opts.ManagedEnterprise = true
		opts.ManagedRuntimeFailure = decision.Reason
		// The block never reaches the gateway, and the managed hook's own
		// failure log is not user-writable: leave a record in the user's
		// data directory for the guardian to report (best effort).
		_ = hookForeignGuardRecord(accountHome, name, event, decision, time.Now())
		return
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	for _, finding := range decision.Findings {
		if !finding.Allowed {
			fmt.Fprintf(stderr, "defenseclaw: warning: unapproved %s hook in %s (sha256:%s); your organization reports it but allows it to run\n", name, finding.Path, finding.Digest)
		}
	}
}

// foreignHookGuardedEvent reports whether the guard applies to an event.
// The managed OpenCode plugin sends its load heartbeat, session lifecycle
// and tool.execute.after telemetry through this hook too; none of them can
// block, so only tool.execute.before is guarded (the plugin also runs
// --foreign-hook-check once at load). Every other connector is guarded on
// every event.
func foreignHookGuardedEvent(connectorName, event string) bool {
	if !strings.EqualFold(strings.TrimSpace(connectorName), enterprisepolicy.ConnectorOpenCode) {
		return true
	}
	return strings.TrimSpace(event) == "tool.execute.before"
}

// standaloneForeignHookGuardBinary is the administrator-owned hook binary
// the standalone Amp and OpenCode plugins run for the foreign-hook guard
// (those plugins call the gateway directly, so the hook-time guard would
// otherwise never run for them), and on Linux and macOS the binary the
// standalone Devin hook command runs in managed mode (the per-user
// devin-hook.sh never ran the guard; Windows already registers the
// administrator-owned binary for Devin), and on Linux and macOS the binary
// the standalone hermes-hook.sh asks for the guard's decision before each
// tool call (Hermes has no managed hook source, so its per-user shell hook
// stays the registered command). Empty for every other connector and on
// any non-standalone profile, so Secure Client and per-user installs render
// unchanged.
func standaloneForeignHookGuardBinary(connectorName string) string {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "amp", enterprisepolicy.ConnectorOpenCode:
	case "devin", enterprisepolicy.ConnectorHermes:
		if runtime.GOOS == "windows" {
			return ""
		}
	default:
		return ""
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return ""
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return ""
	}
	return opts.HookBinary
}

// hookForeignGuardHomes lists the homes an agent may read hook config
// from: the account's home and, when different, the home its environment
// names.
func hookForeignGuardHomes(accountHome string) []string {
	homes := appendDistinctAbs(nil, accountHome)
	for _, home := range hookForeignGuardEnvHomes() {
		homes = appendDistinctAbs(homes, home)
	}
	return homes
}

// foreignHookCheckResult is the JSON the in-agent plugins and the
// standalone Hermes shell hook read from `hook --foreign-hook-check`.
// Anything but {"deny": false} blocks.
type foreignHookCheckResult struct {
	Deny     bool     `json:"deny"`
	Reason   string   `json:"reason,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	// HookOutput is the Hermes block object hermes-hook.sh prints for a
	// denied tool call (Hermes shows its message). Hermes only.
	HookOutput *hermesForeignHookBlock `json:"hook_output,omitempty"`
}

// hermesForeignHookBlock is Hermes' pre_tool_call block response.
type hermesForeignHookBlock struct {
	Action  string `json:"action"`
	Message string `json:"message"`
}

// hermesForeignHookBlockMessage is what Hermes shows when the guard blocks
// a tool call: that DefenseClaw blocked it, the guard's reason (the file,
// the digest and the allowlist key) and the reason code last in
// parentheses, as the other standalone block messages read.
func hermesForeignHookBlockMessage(reason string) string {
	reason = strings.TrimSpace(reason)
	if rest, ok := strings.CutPrefix(reason, hookexec.ForeignHookBlockedReasonPrefix); ok {
		return "DefenseClaw blocked this tool call: " + strings.TrimSpace(rest) + " (" + strings.TrimSuffix(hookexec.ForeignHookBlockedReasonPrefix, ":") + ")"
	}
	return "DefenseClaw blocked this tool call: DefenseClaw is not set up correctly on this computer. Contact your administrator. (" + reason + ")"
}

// runForeignHookCheck evaluates the foreign-hook guard for an in-agent
// plugin (Amp, OpenCode) that calls the gateway directly, or for the
// standalone Hermes shell hook, which runs it before its gateway request
// (Hermes runs every registered shell hook, so the guard cannot run inside
// the gateway request). It reads the caller's {hook_event_name, cwd,
// session_id} from stdin, applies the same summary trust, scan and budget
// as the hook-time guard, records a block for the guardian, and always
// exits 0 with one JSON object: the caller treats a missing or malformed
// answer as a block. Hosts without a standalone summary answer allow, like
// the hook-time guard.
func runForeignHookCheck(connectorName string, stdin io.Reader, stdout io.Writer) int {
	startedAt := time.Now()
	result := foreignHookCheckResult{}
	hermes := strings.EqualFold(strings.TrimSpace(connectorName), enterprisepolicy.ConnectorHermes)
	defer func() {
		if hermes && result.Deny {
			result.HookOutput = &hermesForeignHookBlock{Action: "block", Message: hermesForeignHookBlockMessage(result.Reason)}
		}
		_ = json.NewEncoder(stdout).Encode(result)
	}()
	path, ok := hookForeignGuardSummaryPath()
	if !ok {
		return 0
	}
	summary, err := hookForeignGuardLoad(path)
	if errors.Is(err, enterprisepolicy.ErrNoPublicPolicy) {
		return 0
	}
	if err != nil {
		result = foreignHookCheckResult{Deny: true, Reason: "enterprise_machine_policy_summary_untrusted"}
		return 0
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	policy, ok := summary.Connectors[name]
	if !ok || !policy.Guard {
		return 0
	}
	opts := hookexec.Options{Connector: name, Stdin: stdin}
	facts := captureHookPayloadFacts(&opts)
	decision, accountHome := evaluateHookForeignGuard(name, summary.HookBinary, policy, facts, facts.event, startedAt.Add(hookForeignGuardMaxScan))
	if decision.Deny {
		_ = hookForeignGuardRecord(accountHome, name, facts.event, decision, time.Now())
		result = foreignHookCheckResult{Deny: true, Reason: decision.Reason}
		return 0
	}
	for _, finding := range decision.Findings {
		if !finding.Allowed {
			result.Warnings = append(result.Warnings, fmt.Sprintf("unapproved %s hook in %s (sha256:%s); your organization reports it but allows it to run", name, finding.Path, finding.Digest))
		}
	}
	return 0
}

// hookForeignGuardMaxScan caps the foreign-hook scan; real hook trees
// take milliseconds.
const hookForeignGuardMaxScan = 5 * time.Second

// hookForeignGuardScanBudget gives the scan and gateway session exchange a
// quarter of the request budget each, leaving at least half for the hook's
// ordinary gateway request.
func hookForeignGuardScanBudget(connector, event string) time.Duration {
	budget := hookexec.RequestTimeout(connector, event) / 4
	if budget > hookForeignGuardMaxScan || budget <= 0 {
		budget = hookForeignGuardMaxScan
	}
	return budget
}

// evaluateHookForeignGuard scans every home and working directory the
// agent may load hooks from, in one pass that reads each path once and
// stops at the first unapproved finding (a session start scans everything,
// for the session's snapshot). DefenseClaw's own per-user registration is
// recognized only under the account's home: the hook's data directory and
// $HOME come from the agent's environment (DEFENSECLAW_HOME, HOME), which
// the user controls. With foreign_hooks remove, the result is combined
// with the session's state in the gateway (a session that started with an
// unapproved hook stays denied until the agent restarts), and the agent's config-location environment is
// recorded for the guardian's cleanup.
func evaluateHookForeignGuard(name, hookBinary string, policy enterprisepolicy.PublicConnectorPolicy, facts hookPayloadFacts, event string, deadline time.Time) (enterprisepolicy.GuardDecision, string) {
	accountHome := hookForeignGuardAccountHome()
	owned := []string{}
	if accountHome != "" {
		owned = perUserOwnedHookCommandsForBinary(name, accountHome, "", hookBinary)
	}
	homes := hookForeignGuardHomes(accountHome)
	if len(homes) == 0 {
		return enterprisepolicy.GuardDecision{
			Deny:   true,
			Reason: hookexec.ForeignHookBlockedReasonPrefix + " your organization blocks " + name + " hooks it has not approved, and DefenseClaw cannot determine your home directory to check for them.",
		}, ""
	}
	sessionStart := hookForeignGuardSessionStart(event)
	request := enterprisepolicy.GuardRequest{
		Connector:           name,
		Home:                homes[0],
		Homes:               homes[1:],
		AccountHome:         accountHome,
		HookBinary:          hookBinary,
		Policy:              policy,
		Getenv:              os.Getenv,
		OwnedCommands:       owned,
		HookSurface:         facts.surface,
		Deadline:            deadline,
		StopAtFirstBlocking: !sessionStart,
	}
	if len(facts.workingDirs) > 0 {
		request.WorkingDir = facts.workingDirs[0]
		request.WorkingDirs = facts.workingDirs[1:]
	}
	decision := enterprisepolicy.EvaluateForeignHooks(request)
	if policy.ForeignHooks != config.ForeignHooksRemove {
		return decision, accountHome
	}
	now := time.Now()
	if accountHome != "" {
		if redirect, ok := enterprisepolicy.ObservedEnvRedirect(request); ok {
			_ = hookForeignGuardRecordEnv(accountHome, name, redirect, now)
		}
	}
	update := enterprisepolicy.SessionExchange{
		Key:          enterprisepolicy.SessionKey{Connector: name, Session: facts.session, Process: hookForeignGuardAgentProcess()},
		SessionStart: sessionStart,
		Decision:     decision,
	}
	decision, err := hookForeignGuardExchange(name, event, deadline, update)
	if err != nil {
		// The gateway holds the session record. Without its answer the call
		// is blocked in every fail mode, and the reason must not suggest an
		// unapproved hook that may not exist (the usual cause is a gateway
		// that is stopped or restarting).
		decision = enterprisepolicy.GuardDecision{
			Deny:     true,
			Reason:   foreignHookSessionUnavailableReason,
			Findings: update.Decision.Findings,
		}
	}
	return decision, accountHome
}

func exchangeForeignHookSession(name, event string, scanDeadline time.Time, update enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
	if enterpriseManagedHookRuntimeNoop(name) {
		return enterprisepolicy.GuardDecision{}, fmt.Errorf("standalone hook runtime unavailable")
	}
	opts := buildHookOptionsForRuntime(name, event, "", "closed", true)
	deadline := scanDeadline.Add(hookForeignGuardScanBudget(name, event))
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	data, err := json.Marshal(update)
	if err != nil {
		return enterprisepolicy.GuardDecision{}, err
	}
	response, err := hookexec.ExchangeForeignHookSession(ctx, opts, name, data)
	if err != nil {
		return enterprisepolicy.GuardDecision{}, err
	}
	var decision enterprisepolicy.GuardDecision
	if err := json.Unmarshal(response, &decision); err != nil {
		return enterprisepolicy.GuardDecision{}, err
	}
	if update.Decision.Deny && !decision.Deny || decision.Deny && decision.Reason == "" {
		return enterprisepolicy.GuardDecision{}, fmt.Errorf("invalid session gateway decision")
	}
	return decision, nil
}

// hookForeignGuardSessionStart reports an agent's session-start event,
// where the session's snapshot is taken: Claude Code, Codex and Devin
// SessionStart, Cursor and Copilot sessionStart, Hermes on_session_start
// (Hermes registers its shell hooks when the process starts), and the
// startup checks of the OpenCode and Amp plugins (which load plugins once
// per process).
func hookForeignGuardSessionStart(event string) bool {
	switch strings.ToLower(strings.TrimSpace(event)) {
	case "sessionstart", "session_start", "session.start", "defenseclaw.plugin.loaded", "session.load", "on_session_start":
		return true
	}
	return false
}

// hookPayloadFacts is what the guard reads from the hook payload.
type hookPayloadFacts struct {
	workingDirs []string
	event       string
	// session is the agent's session ID (Claude Code, Codex, Devin and
	// Copilot session_id or sessionId; Cursor conversation_id).
	session string
	// surface is the hook command's --hook-surface marker when the
	// connector lists it (the VS Code Local harness reads more sources).
	surface string
}

// hookForeignGuardSessionKeys name the agent's session ID, in order.
var hookForeignGuardSessionKeys = []string{"session_id", "sessionId", "sessionID", "conversation_id", "conversationId"}

// captureHookPayloadFacts buffers the start of the hook payload to read the
// agent's working directory, the event name (for the block record) and the
// session ID, then hands hookexec an identical stream. The process working
// directory is always included because the agent loads project hooks from
// where it runs.
func captureHookPayloadFacts(opts *hookexec.Options) hookPayloadFacts {
	facts := hookPayloadFacts{workingDirs: []string{}}
	if cwd, err := os.Getwd(); err == nil {
		facts.workingDirs = appendDistinctAbs(facts.workingDirs, cwd)
	}
	source := opts.Stdin
	if source == nil {
		source = os.Stdin
	}
	buffered, err := io.ReadAll(io.LimitReader(source, hookForeignGuardPayloadLimit))
	opts.Stdin = io.MultiReader(bytes.NewReader(buffered), source)
	if err != nil {
		return facts
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(buffered, &payload) != nil {
		return facts
	}
	for _, key := range []string{"hook_event_name", "event"} {
		var event string
		if json.Unmarshal(payload[key], &event) == nil && strings.TrimSpace(event) != "" {
			facts.event = strings.TrimSpace(event)
			break
		}
	}
	for _, key := range hookForeignGuardSessionKeys {
		var session string
		if json.Unmarshal(payload[key], &session) == nil && strings.TrimSpace(session) != "" {
			facts.session = strings.TrimSpace(session)
			break
		}
	}
	for _, key := range []string{"cwd", "working_directory", "workingDirectory"} {
		var value string
		if json.Unmarshal(payload[key], &value) == nil {
			facts.workingDirs = appendDistinctAbs(facts.workingDirs, value)
		}
	}
	for _, key := range []string{"workspace_roots", "workspaceRoots"} {
		var values []string
		if json.Unmarshal(payload[key], &values) == nil {
			for _, value := range values {
				facts.workingDirs = appendDistinctAbs(facts.workingDirs, value)
			}
		}
	}
	return facts
}

// perUserOwnedHookCommands lists DefenseClaw's own per-user registration
// commands for the default per-user data dir under home and any explicit
// data dir.
func perUserOwnedHookCommands(name, home, dataDir string) []string {
	return perUserOwnedHookCommandsForBinary(name, home, dataDir, "")
}

// perUserOwnedHookCommandsForBinary also owns the per-user commands rendered
// for the administrator's published hookBinary: the hook process cannot
// resolve the launcher the guardian registered.
func perUserOwnedHookCommandsForBinary(name, home, dataDir, hookBinary string) []string {
	dirs := appendDistinctAbs(nil, filepath.Join(home, ".defenseclaw"))
	dirs = appendDistinctAbs(dirs, dataDir)
	owned := []string{}
	for _, dir := range dirs {
		owned = append(owned, connector.PerUserOwnedHookCommandsForBinary(name, dir, hookBinary)...)
	}
	return owned
}

func appendDistinctAbs(list []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || !filepath.IsAbs(value) {
		return list
	}
	value = filepath.Clean(value)
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

// devinDesktopRestartNote explains restarting the agent to a Devin Desktop
// user: one Devin Local process (devin acp) serves every Desktop tab, so a
// session block keyed to that process holds in every tab until Desktop
// restarts.
const devinDesktopRestartNote = "Devin Desktop runs every tab in one Devin Local process, so closing a tab does not restart the agent: quit and reopen Devin Desktop."

// withDesktopRestartNote adds devinDesktopRestartNote to a Devin block that
// asks for a restart when the agent runs under Devin Desktop (or the
// Desktop's legacy process name).
func withDesktopRestartNote(name, host, reason string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	desktop := strings.HasPrefix(host, "devin") || strings.HasPrefix(host, legacyconnector.ProcessName)
	if name != "devin" || !desktop || !strings.Contains(reason, "restart") {
		return reason
	}
	return reason + " " + devinDesktopRestartNote
}
