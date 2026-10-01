// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package enterprisepolicy publishes, verifies and removes DefenseClaw's
// hooks in vendor machine policy (Codex requirements.toml, Claude Code
// managed settings, Cursor enterprise hooks, Copilot policy hooks) for the
// standalone managed_enterprise profile, and implements the foreign-hook
// guard for connectors whose vendors offer no managed-hooks-only lock.
//
// Every writer here merges instead of replacing: administrator-authored
// settings and hooks survive publish, repair and removal, DefenseClaw owns
// only entries it can identify exactly, and removal restores the recorded
// preimage when nobody else changed the file.
//
// The Secure Client profile never calls this package; its Windows machine
// policy stays on the certified code paths in internal/gateway/connector
// and internal/enterprisehooks.
package enterprisepolicy

import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Routes describe how a connector is protected in the standalone profile.
const (
	// RouteMachinePolicy publishes DefenseClaw's hooks through a vendor
	// machine policy source that standard users cannot write.
	RouteMachinePolicy = "machine_policy"
	// RoutePerUser registers the admin-owned hook binary in each enrolled
	// user's own agent config; the guardian repairs drift.
	RoutePerUser = "per_user"
	// RouteACP enrolls through the managed ACP mediator.
	RouteACP = "acp"
	// RouteUnsupported marks connectors the managed profile refuses.
	RouteUnsupported = "unsupported"
)

// Connector names with a machine policy implementation.
const (
	ConnectorCodex      = "codex"
	ConnectorClaudeCode = "claudecode"
	ConnectorCursor     = "cursor"
	ConnectorCopilot    = "copilot"
	ConnectorOpenCode   = "opencode"
)

// ErrUnsupported reports a connector/OS pair without a machine policy
// target.
var ErrUnsupported = errors.New("machine policy is not supported for this connector")

// Options carries everything a target needs. Paths are resolved against
// Root so tests can run the real writers inside a temporary tree.
type Options struct {
	// GOOS is the target platform (default runtime.GOOS).
	GOOS string
	// Root is prepended to every unix machine path ("" in production).
	Root string
	// WindowsProgramFiles/WindowsProgramData are the trusted machine roots
	// (resolved by the lifecycle from protected HKLM registration).
	WindowsProgramFiles string
	WindowsProgramData  string
	// HookBinary is the absolute path of the admin-owned hook executable.
	HookBinary string
	// StateDir is the root-only directory holding ownership records and
	// preimages (the lifecycle passes <layout.LifecycleDir>/machine-policy).
	StateDir string
	// PublicPolicyPath is the world-readable, administrator-owned summary
	// the hook-side foreign-hook guard reads (<layout.ConfigDir>/machine-policy.json).
	PublicPolicyPath string
	// AgentVersions optionally pins the client version per connector; it
	// selects the hook contract and gates version-dependent vendor
	// features (Claude managedSourcesBehavior merge needs >= 2.1.242).
	AgentVersions map[string]string
	// Policies are the resolved per-connector enterprise.machine_policy
	// settings; a connector missing from the map uses the secure defaults.
	Policies map[string]config.ResolvedConnectorPolicy
	// ClaudeVersionFloor is enterprise.machine_policy.connectors.claudecode.version_floor
	// (enforce, report or off); "" means the default, enforce.
	ClaudeVersionFloor string
	// Now is injectable for tests.
	Now func() time.Time
	// OpenCodePluginPath is the absolute path of the administrator-owned
	// managed OpenCode plugin artifact (see OpenCodeManagedPluginPath).
	// OpenCode moves from the per-user route to machine policy while a
	// trusted file is installed there.
	OpenCodePluginPath string
	// OpenCodePluginPlanned tells Route that the caller installs the managed
	// OpenCode plugin before it publishes (the unix lifecycle renders it with
	// the deployment's files), so planning puts OpenCode on machine policy
	// before the file exists. Reconcile still requires the installed file.
	OpenCodePluginPlanned bool
	// SkipTrustChecks disables ancestor ownership checks; only tests set it.
	SkipTrustChecks bool
}

func runtimeGOOS() string { return runtime.GOOS }

func (o Options) goos() string {
	if o.GOOS != "" {
		return o.GOOS
	}
	return runtime.GOOS
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

// PolicyFor returns the resolved policy for connector, defaulting to the
// secure built-ins.
func (o Options) PolicyFor(connector string) config.ResolvedConnectorPolicy {
	if policy, ok := o.Policies[connector]; ok && policy.Ownership != "" {
		return policy
	}
	return config.EnterpriseMachinePolicyConfig{}.PolicyFor(connector)
}

func (o Options) agentVersion(connector string) string {
	if o.AgentVersions == nil {
		return ""
	}
	return strings.TrimSpace(o.AgentVersions[connector])
}

// Validate checks the options shared by every target.
func (o Options) Validate() error {
	if strings.TrimSpace(o.HookBinary) == "" {
		return errors.New("enterprise policy: hook binary path is required")
	}
	if o.goos() == "windows" {
		if !windowsAbsolute(o.HookBinary) {
			return fmt.Errorf("enterprise policy: hook binary %q is not an absolute Windows path", o.HookBinary)
		}
		if !windowsAbsolute(o.WindowsProgramData) || !windowsAbsolute(o.WindowsProgramFiles) {
			return errors.New("enterprise policy: trusted Windows Program Files and ProgramData roots are required")
		}
	} else if !strings.HasPrefix(o.HookBinary, "/") {
		return fmt.Errorf("enterprise policy: hook binary %q is not absolute", o.HookBinary)
	}
	if strings.ContainsAny(o.HookBinary, "\x00\r\n'\"") {
		return fmt.Errorf("enterprise policy: hook binary path %q contains characters that cannot be quoted safely", o.HookBinary)
	}
	if err := validOpenCodePluginPath(o); err != nil {
		return fmt.Errorf("enterprise policy: %w", err)
	}
	return nil
}

func windowsAbsolute(value string) bool {
	return len(value) >= 3 && value[1] == ':' && value[2] == '\\' &&
		((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z'))
}

// State is one connector's machine policy report.
type State struct {
	Connector        string   `json:"connector"`
	Route            string   `json:"route"`
	Ownership        string   `json:"ownership"`
	Lock             string   `json:"lock,omitempty"`
	EffectiveLock    string   `json:"effective_lock,omitempty"`
	ForeignHooks     string   `json:"foreign_hooks,omitempty"`
	Paths            []string `json:"paths,omitempty"`
	OwnedEntries     int      `json:"owned_entries"`
	ForeignEntries   int      `json:"foreign_entries"`
	HigherPrecedence []string `json:"higher_precedence,omitempty"`
	Conflicts        []string `json:"conflicts,omitempty"`
	Pending          []string `json:"pending,omitempty"`
	Details          []string `json:"details,omitempty"`
	Changed          bool     `json:"changed"`
	Covered          bool     `json:"covered"`
	// Drift marks DefenseClaw entries that are in place but differ from
	// what the next publish writes (a policy file mode agents cannot read
	// through, a Claude Code floor drop-in it must withdraw). A conflict
	// says what; VerifyAll does not report the connector in place, so the
	// lifecycle's ensure re-applies.
	Drift          bool   `json:"drift,omitempty"`
	LiveVerifiedAt string `json:"live_verified_at,omitempty"`
	// VersionFloor is Claude Code's requiredMinimumVersion state (claudecode
	// only).
	VersionFloor *VersionFloorState `json:"version_floor,omitempty"`
}

// ToStatus maps the report onto the shared lifecycle result schema.
func (s State) ToStatus() enterprisestatus.MachinePolicyState {
	return enterprisestatus.MachinePolicyState{
		Ownership:        s.Ownership,
		Lock:             s.Lock,
		EffectiveLock:    s.EffectiveLock,
		OwnedEntries:     s.OwnedEntries,
		ForeignEntries:   s.ForeignEntries,
		HigherPrecedence: append([]string(nil), s.HigherPrecedence...),
		Conflicts:        append([]string(nil), s.Conflicts...),
		LiveVerifiedAt:   s.LiveVerifiedAt,
	}
}

func (s *State) conflict(format string, args ...any) {
	s.Conflicts = append(s.Conflicts, fmt.Sprintf(format, args...))
}

func (s *State) detail(format string, args ...any) {
	s.Details = append(s.Details, fmt.Sprintf(format, args...))
}

func (s *State) finish() {
	sort.Strings(s.HigherPrecedence)
	s.Covered = s.Route == RouteMachinePolicy && s.OwnedEntries > 0 && len(s.Conflicts) == 0 && len(s.HigherPrecedence) == 0
}

// Target is one connector's machine policy implementation.
type Target interface {
	Name() string
	// Paths returns the machine files the target owns or inspects on goos.
	Paths(opts Options) ([]string, error)
	// Reconcile publishes DefenseClaw's entries (merge) or only verifies
	// them (verify_only); it never removes administrator content.
	Reconcile(opts Options) (State, error)
	// Verify inspects without writing.
	Verify(opts Options) (State, error)
	// RemoveOwned removes only DefenseClaw-owned content and restores the
	// recorded preimage when the file is otherwise unchanged.
	RemoveOwned(opts Options) (State, error)
	// Export renders DefenseClaw's entries for an administrator to paste
	// into their own policy source.
	Export(opts Options, format string) ([]byte, error)
}

var targets = map[string]Target{
	ConnectorCodex:      codexTarget{},
	ConnectorClaudeCode: claudeTarget{},
	ConnectorCursor:     cursorTarget{},
	ConnectorCopilot:    copilotTarget{},
	ConnectorOpenCode:   opencodeTarget{},
}

// TargetFor returns the machine policy target for connector.
func TargetFor(connector string) (Target, bool) {
	target, ok := targets[strings.ToLower(strings.TrimSpace(connector))]
	return target, ok
}

// RouteFor reports how the standalone profile protects connector on goos.
func RouteFor(connector, goos string) string {
	connector = strings.ToLower(strings.TrimSpace(connector))
	switch connector {
	case ConnectorCodex, ConnectorClaudeCode, ConnectorCursor, ConnectorCopilot:
		return RouteMachinePolicy
	case "kiro":
		// Kiro has no vendor mechanism that delivers hooks from a machine
		// location (its managed-settings.json carries permission rules
		// only), so on Linux and macOS the standalone guardian registers
		// the hook in each enrolled user's global ~/.kiro/hooks, which Kiro
		// IDE and kiro-cli --v3 merge with every other scope, plus the CLI
		// 2.x agent. The Windows guardian does not enroll Kiro: kiro-cli.exe
		// records its version nowhere DefenseClaw can read without running
		// it, and Windows discovery runs nothing. Kiro there is protected
		// through `defenseclaw-gateway enterprise acp`, which stays
		// available on every OS for editors that start Kiro over ACP.
		if goos == "windows" {
			return RouteACP
		}
		return RoutePerUser
	case "deepseek":
		return RouteUnsupported // Preview bridge can be disabled by user patches and fails open.
	case "openclaw", "zeptoclaw":
		return RouteUnsupported
	case "openhands", "omnigent":
		if goos == "windows" {
			return RouteUnsupported
		}
		return RoutePerUser
	case "devin", "antigravity", "hermes", "opencode", "amp":
		return RoutePerUser
	default:
		return RouteUnsupported
	}
}

// Route is RouteFor with the options that can move a connector onto
// machine policy (OpenCode needs the trusted managed plugin artifact at
// OpenCodePluginPath, or the caller's plan to install it).
func (o Options) Route(connector string) string {
	connector = strings.ToLower(strings.TrimSpace(connector))
	if connector == ConnectorOpenCode && o.openCodeMachineRoute() {
		return RouteMachinePolicy
	}
	return RouteFor(connector, o.goos())
}

// MachinePolicyConnectors returns the subset of connectors whose hooks the
// lifecycle publishes through machine policy (sorted), honoring
// ownership: off. The lifecycle records it in the runtime descriptor.
func MachinePolicyConnectors(opts Options, connectors []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, name := range connectors {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if opts.Route(name) != RouteMachinePolicy {
			continue
		}
		if opts.PolicyFor(name).Ownership == config.MachinePolicyOwnershipOff {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// VendorMachinePolicyConnectors are the connectors whose only standalone
// route on goos is vendor machine policy (Codex, Claude Code, Cursor and
// Copilot; OpenCode falls back to its per-user plugin), sorted. The Linux
// and macOS guardian keeps a per-user registration for one of them only
// while the target manifest enrolls that user for it per user.
func VendorMachinePolicyConnectors(goos string) []string {
	out := []string{}
	for _, name := range targetNames() {
		if RouteFor(name, goos) == RouteMachinePolicy {
			out = append(out, name)
		}
	}
	return out
}

// OwnershipOffConnectors returns the connectors cfg names whose route on
// goos is vendor machine policy and whose machine policy the administrator
// leaves alone (ownership: "off"), sorted. On Linux and macOS DefenseClaw
// gives them no route: it writes no machine policy for them and does not
// move them to per-user hooks either.
func OwnershipOffConnectors(cfg *config.Config, goos string) []string {
	out := []string{}
	if cfg == nil {
		return out
	}
	for _, name := range StandaloneConnectors(cfg) {
		if RouteFor(name, goos) == RouteMachinePolicy &&
			cfg.Enterprise.MachinePolicy.PolicyFor(name).Ownership == config.MachinePolicyOwnershipOff {
			out = append(out, name)
		}
	}
	return out
}
