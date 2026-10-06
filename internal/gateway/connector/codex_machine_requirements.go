// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/pelletier/go-toml/v2"
)

const (
	WindowsCodexMachineRequirementsSchemaVersion = 2
	windowsCodexMachineRequirementsSchema        = WindowsCodexMachineRequirementsSchemaVersion
	windowsCodexMachineRequirementsLimit         = 2 << 20
	windowsCodexMachineOwnershipLimit            = 4 << 20
	windowsCodexManagedStateLimit                = 1 << 20
	windowsCodexManagedStateFile                 = ".defenseclaw-managed-hooks.state"
	windowsCodexManagedLockFile                  = ".defenseclaw-managed-hooks.lock"
)

const (
	// WindowsClaudeEffectivePolicyUnverifiedReason is returned because
	// Claude's managed tier is first-source-wins and protected local file
	// bytes alone do not prove that DefenseClaw is the effective source.
	WindowsClaudeEffectivePolicyUnverifiedReason = "claude_effective_policy_unverified"
	WindowsApprovedAgentClientsEnforcedEnv       = "DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED"
	WindowsClaudeEffectivePolicyVerifiedEnv      = "DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED"
	WindowsGatewayServiceNameEnv                 = "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME"
)

// WindowsCodexMachineRequirementsOptions identifies the exact protected
// machine policy and ownership files. Production callers derive these paths
// from Windows Known Folders, the running installed gateway, and protected
// deployment metadata; none of them are accepted as public CLI flags.
type WindowsCodexMachineRequirementsOptions struct {
	RequirementsPath   string
	ManagedDir         string
	HookBinary         string
	OwnershipPath      string
	ManagedStatePath   string
	GatewayAddr        string
	GatewayServiceName string
	// AgentApplicationControlEnforced is authenticated installer evidence
	// that WDAC/AppLocker restricts every enabled enterprise agent to approved
	// binaries.
	AgentApplicationControlEnforced bool
	EnterpriseTargetEnabled         bool
	// ClaudeEffectivePolicyVerified records authenticated certification of
	// the effective first-source-wins Claude policy. It is surfaced here for
	// the aggregate Windows deployment report; the Codex requirements API
	// does not independently decide whether Claude is enabled.
	ClaudeEffectivePolicyVerified bool
	ClaudeTargetEnabled           bool
	CodexTargetEnabled            bool
	CursorTargetEnabled           bool
	// HookContractID binds every managed group's command to its Codex event
	// and this hook contract. The hook refuses a Codex invocation that does
	// not carry both, so an unbound command never reaches the gateway. Only
	// the standalone profile sets it (WindowsCodexStandaloneHookContract);
	// the Secure Client profile keeps its certified command byte for byte.
	HookContractID string
}

// WindowsCodexManagedRuntimeTarget is the non-secret mapping a standard-user
// hook process needs to select its administrator-authorized runtime. The
// adjacent state file is readable by BUILTIN\Users but writable only by
// Administrators and LocalSystem.
type WindowsCodexManagedRuntimeTarget struct {
	SID     string `json:"sid"`
	DataDir string `json:"data_dir"`
}

type WindowsCodexManagedRuntimeRegistry struct {
	Active             bool
	GatewayAddr        string
	GatewayServiceName string
	Targets            []WindowsCodexManagedRuntimeTarget
}

// WindowsCodexMachineRequirementsReport is stable machine-readable output for
// the installer and guardian. Disposition distinguishes exact preimage restore
// from surgical removal that preserves later unrelated administrator edits.
type WindowsCodexMachineRequirementsReport struct {
	SchemaVersion                       int    `json:"schema_version"`
	Action                              string `json:"action"`
	OK                                  bool   `json:"ok"`
	Changed                             bool   `json:"changed"`
	Disposition                         string `json:"disposition"`
	RequirementsPath                    string `json:"requirements_path"`
	OwnershipPath                       string `json:"ownership_path"`
	ManagedStatePath                    string `json:"managed_state_path"`
	ManagedDir                          string `json:"managed_dir"`
	HookBinary                          string `json:"hook_binary"`
	GatewayAddr                         string `json:"gateway_addr"`
	GatewayServiceName                  string `json:"gateway_service_name"`
	RequirementsExisted                 bool   `json:"requirements_existed"`
	OwnershipExisted                    bool   `json:"ownership_existed"`
	ManagedStateExisted                 bool   `json:"managed_state_existed"`
	ManagedStateRemoved                 bool   `json:"managed_state_removed"`
	ManagedStateRemovedOrAbsent         bool   `json:"managed_state_removed_or_absent"`
	SafeToRemoveBinary                  bool   `json:"safe_to_remove_binary"`
	SurvivingOwnedPathReferences        int    `json:"surviving_owned_path_references"`
	AgentApplicationControlPrerequisite string `json:"agent_application_control_prerequisite"`
	AgentApplicationControlEnforced     bool   `json:"agent_application_control_enforced"`
	// ApprovedClientEnforced is retained as an explicit schema-v2 alias for
	// installer/certification consumers that predate the all-agent name.
	ApprovedClientEnforced        bool     `json:"approved_client_enforced"`
	ApprovedAgentClientsEnforced  bool     `json:"approved_agent_clients_enforced"`
	ClaudeTargetEnabled           bool     `json:"claude_target_enabled"`
	ClaudeEffectivePolicyVerified bool     `json:"claude_effective_policy_verified"`
	CodexTargetEnabled            bool     `json:"codex_target_enabled"`
	CursorTargetEnabled           bool     `json:"cursor_target_enabled"`
	SecurityComplete              bool     `json:"security_complete"`
	PreimageSHA256                string   `json:"preimage_sha256,omitempty"`
	PostimageSHA256               string   `json:"postimage_sha256,omitempty"`
	ManagedEvents                 []string `json:"managed_events"`
	Details                       []string `json:"details,omitempty"`
	Error                         string   `json:"error,omitempty"`
}

type windowsCodexMachineOwnership struct {
	SchemaVersion    int    `json:"schema_version"`
	RequirementsPath string `json:"requirements_path"`
	ManagedDir       string `json:"managed_dir"`
	HookBinary       string `json:"hook_binary"`
	PreimageExisted  bool   `json:"preimage_existed"`
	Preimage         []byte `json:"preimage,omitempty"`
	PreimageSHA256   string `json:"preimage_sha256"`
	PostimageSHA256  string `json:"postimage_sha256"`
	Pending          bool   `json:"pending,omitempty"`
}

type windowsCodexManagedRuntimeState struct {
	SchemaVersion      int                                `json:"schema_version"`
	RequirementsPath   string                             `json:"requirements_path"`
	RequirementsSHA256 string                             `json:"requirements_sha256"`
	HookExecutable     string                             `json:"hook_executable"`
	GatewayAddr        string                             `json:"gateway_addr"`
	GatewayServiceName string                             `json:"gateway_service_name"`
	Targets            []WindowsCodexManagedRuntimeTarget `json:"targets"`
}

func windowsCodexMachineReport(action string, opts WindowsCodexMachineRequirementsOptions) WindowsCodexMachineRequirementsReport {
	events := make([]string, 0, len(codexHookGroups))
	for _, group := range codexHookGroups {
		events = append(events, group.eventType)
	}
	sort.Strings(events)
	return WindowsCodexMachineRequirementsReport{
		SchemaVersion:                       windowsCodexMachineRequirementsSchema,
		Action:                              action,
		RequirementsPath:                    opts.RequirementsPath,
		OwnershipPath:                       opts.OwnershipPath,
		ManagedStatePath:                    opts.ManagedStatePath,
		ManagedDir:                          opts.ManagedDir,
		HookBinary:                          opts.HookBinary,
		GatewayAddr:                         opts.GatewayAddr,
		GatewayServiceName:                  opts.GatewayServiceName,
		ManagedEvents:                       events,
		AgentApplicationControlPrerequisite: "wdac_or_applocker_approved_agent_client_rules",
		AgentApplicationControlEnforced:     opts.AgentApplicationControlEnforced,
		ApprovedClientEnforced:              opts.AgentApplicationControlEnforced,
		ApprovedAgentClientsEnforced:        opts.AgentApplicationControlEnforced,
		ClaudeTargetEnabled:                 opts.ClaudeTargetEnabled,
		ClaudeEffectivePolicyVerified:       opts.ClaudeEffectivePolicyVerified,
		CodexTargetEnabled:                  opts.CodexTargetEnabled,
		CursorTargetEnabled:                 opts.CursorTargetEnabled,
	}
}

func NormalizeWindowsManagedGatewayAddr(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", fmt.Errorf("managed gateway address %q is not canonical", value)
	}
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("managed gateway address %q is not host:port: %w", value, err)
	}
	if host != "127.0.0.1" {
		return "", fmt.Errorf(
			"managed gateway address %q must use exact canonical 127.0.0.1",
			value,
		)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != rawPort {
		return "", fmt.Errorf("managed gateway address %q has a noncanonical port", value)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func ValidateWindowsManagedGatewayServiceName(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 256 ||
		strings.ContainsAny(value, "\x00\r\n\\/") {
		return fmt.Errorf("managed gateway service name %q is invalid", value)
	}
	return nil
}

func windowsCodexMachineHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func windowsCodexManagedHookCommand(hookBinary string) string {
	script := strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		"$env:NoDefaultCurrentDirectoryInExePath='1'",
		"& " + powershellQuoteLiteral(hookBinary) + " " + nativeHookFlag + "codex --enterprise-managed",
		"exit $LASTEXITCODE",
	}, "; ")
	return windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + powershellEncodedCommand(script)
}

// codexMachineRequirementsLayout names the platform-specific pieces of a
// Codex machine requirements document (requirements.toml): the key and value
// of the managed hook directory and the exact DefenseClaw handler every event
// group must carry. The isolation controls (allow_managed_hooks_only and
// features.hooks), the merge rules and the exact-group verification are
// shared, so the Windows machine-policy installer and the Linux sandbox image
// render and verify the same document shape.
type codexMachineRequirementsLayout struct {
	managedDirKey string
	managedDir    string
	samePath      func(left, right string) bool
	groups        []codexHookGroup
	handler       func(codexHookGroup) map[string]interface{}
}

// windowsCodexBoundManagedHookCommand is the standalone command of one
// managed group. It names the group's event and the hook contract, which
// the hook requires, and starts the GUI-subsystem launcher through the
// awaited Process.Start statements (windowsAwaitedHookStatements): the
// PowerShell call operator does not wait for a GUI-subsystem process, so its
// exit code (2 blocks) and stdout never reached Codex and every decision was
// lost.
func windowsCodexBoundManagedHookCommand(hookBinary, event, contractID string) string {
	arguments := []string{"hook", "--connector", "codex", "--enterprise-managed", "--event", event, "--hook-contract", contractID}
	script := strings.Join(append([]string{
		"$ErrorActionPreference='Stop'",
		"$env:NoDefaultCurrentDirectoryInExePath='1'",
	}, windowsAwaitedHookStatements(hookBinary, arguments)...), "; ")
	return windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + powershellEncodedCommand(script)
}

// windowsCodexManagedHookCommandFor is the managed command opts publishes
// for event.
func windowsCodexManagedHookCommandFor(opts WindowsCodexMachineRequirementsOptions, event string) string {
	if contract := strings.TrimSpace(opts.HookContractID); contract != "" {
		return windowsCodexBoundManagedHookCommand(opts.HookBinary, event, contract)
	}
	return windowsCodexManagedHookCommand(opts.HookBinary)
}

// windowsCodexMachineHandler is the one DefenseClaw handler a Windows managed
// group carries for command.
func windowsCodexMachineHandler(command string, timeout int) map[string]interface{} {
	return map[string]interface{}{
		"type":            "command",
		"command":         command,
		"command_windows": command,
		"timeout":         timeout,
	}
}

func windowsCodexMachineLayout(opts WindowsCodexMachineRequirementsOptions) codexMachineRequirementsLayout {
	return codexMachineRequirementsLayout{
		managedDirKey: "windows_managed_dir",
		managedDir:    opts.ManagedDir,
		samePath:      sameWindowsCodexMachinePath,
		groups:        codexHookGroups,
		handler: func(group codexHookGroup) map[string]interface{} {
			return windowsCodexMachineHandler(windowsCodexManagedHookCommandFor(opts, group.eventType), group.timeout)
		},
	}
}

func (l codexMachineRequirementsLayout) expectedGroup(group codexHookGroup) map[string]interface{} {
	result := map[string]interface{}{
		"hooks": []interface{}{l.handler(group)},
	}
	if group.matcher != "" {
		result["matcher"] = group.matcher
	}
	return result
}

func (l codexMachineRequirementsLayout) groupMatches(raw interface{}, expected codexHookGroup) bool {
	group, ok := raw.(map[string]interface{})
	if !ok || len(group) != 1 && len(group) != 2 {
		return false
	}
	matcher, hasMatcher := group["matcher"]
	if expected.matcher == "" {
		if hasMatcher {
			return false
		}
	} else if value, ok := matcher.(string); !ok || value != expected.matcher {
		return false
	}
	handlers, ok := group["hooks"].([]interface{})
	if !ok || len(handlers) != 1 {
		return false
	}
	handler, ok := handlers[0].(map[string]interface{})
	want := l.handler(expected)
	if !ok || len(handler) != len(want) {
		return false
	}
	for key, value := range want {
		if key == "timeout" {
			continue
		}
		if handler[key] != value {
			return false
		}
	}
	timeout, ok := codexInteger(handler["timeout"])
	return ok && timeout == expected.timeout
}

// reconcile merges the DefenseClaw managed hook matrix into cfg in place,
// preserving unrelated administrator content and refusing contradictory
// isolation controls.
func (l codexMachineRequirementsLayout) reconcile(cfg map[string]interface{}) error {
	if existing, present := cfg["allow_managed_hooks_only"]; present {
		value, ok := existing.(bool)
		if !ok {
			return fmt.Errorf("allow_managed_hooks_only has unsupported type %T", existing)
		}
		if !value {
			return errors.New("allow_managed_hooks_only=false conflicts with required DefenseClaw managed-hook isolation")
		}
	}
	cfg["allow_managed_hooks_only"] = true

	features, exists := cfg["features"].(map[string]interface{})
	if existing, present := cfg["features"]; present && !exists {
		return fmt.Errorf("features has unsupported type %T", existing)
	}
	if !exists {
		features = map[string]interface{}{}
	}
	if existing, present := features["hooks"]; present {
		value, ok := existing.(bool)
		if !ok {
			return fmt.Errorf("features.hooks has unsupported type %T", existing)
		}
		if !value {
			return errors.New("features.hooks=false conflicts with required DefenseClaw managed hooks")
		}
	}
	features["hooks"] = true
	cfg["features"] = features

	hooks, exists := cfg["hooks"].(map[string]interface{})
	if existing, present := cfg["hooks"]; present && !exists {
		return fmt.Errorf("hooks has unsupported type %T", existing)
	}
	if !exists {
		hooks = map[string]interface{}{}
	}
	if _, present := hooks["state"]; present {
		return errors.New("hooks.state is not valid in DefenseClaw managed requirements")
	}
	if existing, present := hooks[l.managedDirKey]; present {
		value, ok := existing.(string)
		if !ok {
			return fmt.Errorf("hooks.%s has unsupported type %T", l.managedDirKey, existing)
		}
		if !l.samePath(value, l.managedDir) {
			// Strict mode preserves refuse-on-drift: a hardened
			// deployment MUST refuse a stale hooks.<managed_dir>
			// value instead of silently overwriting it. The managed-
			// hooks adoptable fix in codex_machine_requirements_
			// windows.go also honors strict mode for the ownership
			// record; this is its on-wire mirror.
			if managed.TrustStrictAncestors() {
				return fmt.Errorf(
					"hooks.%s=%q conflicts with protected managed directory %q",
					l.managedDirKey,
					value,
					l.managedDir,
				)
			}
			// Bulldoze: a prior unsigned certification install at a
			// scoped path left the managed-dir value pointing at its
			// (now stale) bin directory. Refusing stranded the current
			// install. Overwrite with the current install's canonical
			// managedDir (the next statement already does this) and
			// emit a diagnostic so a DART review can grep the recovery.
			fmt.Fprintf(os.Stderr,
				"[enterprise-hooks] reclaiming stale Codex hooks.%s = %q, "+
					"overwriting with current install's canonical managedDir %q\n",
				l.managedDirKey, value, l.managedDir)
		}
	}
	hooks[l.managedDirKey] = l.managedDir

	for _, expected := range l.groups {
		rawGroups, present := hooks[expected.eventType]
		var groups []interface{}
		if present {
			var ok bool
			groups, ok = rawGroups.([]interface{})
			if !ok {
				return fmt.Errorf("hooks.%s has unsupported type %T", expected.eventType, rawGroups)
			}
		}
		found := false
		for _, candidate := range groups {
			if l.groupMatches(candidate, expected) {
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, l.expectedGroup(expected))
		}
		hooks[expected.eventType] = groups
	}
	cfg["hooks"] = hooks
	return nil
}

// verify requires pinned isolation controls, the protected managed directory
// and exactly one DefenseClaw group per managed event.
func (l codexMachineRequirementsLayout) verify(cfg map[string]interface{}) error {
	managedOnly, ok := cfg["allow_managed_hooks_only"].(bool)
	if !ok || !managedOnly {
		return errors.New("allow_managed_hooks_only is not pinned true")
	}
	features, ok := cfg["features"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("features has unsupported type %T", cfg["features"])
	}
	hooksEnabled, ok := features["hooks"].(bool)
	if !ok || !hooksEnabled {
		return errors.New("features.hooks is not pinned true")
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("hooks has unsupported type %T", cfg["hooks"])
	}
	if _, present := hooks["state"]; present {
		return errors.New("hooks.state must be absent from managed requirements")
	}
	managedDir, ok := hooks[l.managedDirKey].(string)
	if !ok || !l.samePath(managedDir, l.managedDir) {
		return fmt.Errorf(
			"hooks.%s=%q does not match protected managed directory %q",
			l.managedDirKey,
			managedDir,
			l.managedDir,
		)
	}
	for _, expected := range l.groups {
		groups, ok := hooks[expected.eventType].([]interface{})
		if !ok {
			return fmt.Errorf("hooks.%s has unsupported type %T", expected.eventType, hooks[expected.eventType])
		}
		found := 0
		for _, candidate := range groups {
			if l.groupMatches(candidate, expected) {
				found++
			}
		}
		if found != 1 {
			return fmt.Errorf(
				"hooks.%s has %d exact DefenseClaw managed groups, want 1",
				expected.eventType,
				found,
			)
		}
	}
	return nil
}

func parseWindowsCodexRequirements(raw []byte) (map[string]interface{}, error) {
	cfg := map[string]interface{}{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return cfg, nil
	}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func reconcileWindowsCodexRequirements(
	raw []byte,
	opts WindowsCodexMachineRequirementsOptions,
) ([]byte, bool, error) {
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		return nil, false, fmt.Errorf("parse Codex requirements: %w", err)
	}
	if err := windowsCodexMachineLayout(opts).reconcile(cfg); err != nil {
		return nil, false, err
	}

	rendered, err := toml.Marshal(cfg)
	if err != nil {
		return nil, false, fmt.Errorf("marshal Codex requirements: %w", err)
	}
	if len(rendered) > windowsCodexMachineRequirementsLimit {
		return nil, false, fmt.Errorf(
			"rendered Codex requirements exceed %d bytes",
			windowsCodexMachineRequirementsLimit,
		)
	}
	if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
		return nil, false, fmt.Errorf("verify rendered Codex requirements: %w", err)
	}
	return rendered, !bytes.Equal(raw, rendered), nil
}

func verifyWindowsCodexRequirementsBytes(
	raw []byte,
	opts WindowsCodexMachineRequirementsOptions,
) error {
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		return fmt.Errorf("parse Codex requirements: %w", err)
	}
	return windowsCodexMachineLayout(opts).verify(cfg)
}

func windowsCodexMachineGroupMatches(
	raw interface{},
	expected struct {
		eventType string
		matcher   string
		timeout   int
	},
	opts WindowsCodexMachineRequirementsOptions,
) bool {
	return windowsCodexMachineGroupHasCommand(raw, expected, windowsCodexManagedHookCommandFor(opts, expected.eventType))
}

func windowsCodexMachineGroupHasCommand(
	raw interface{},
	expected struct {
		eventType string
		matcher   string
		timeout   int
	},
	command string,
) bool {
	layout := codexMachineRequirementsLayout{
		handler: func(group codexHookGroup) map[string]interface{} {
			return windowsCodexMachineHandler(command, group.timeout)
		},
	}
	return layout.groupMatches(raw, codexHookGroup(expected))
}

func sameWindowsCodexMachinePath(left, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func windowsCodexRequirementsContainExactManagedHook(
	raw []byte,
	opts WindowsCodexMachineRequirementsOptions,
) (bool, error) {
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		return false, err
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return false, nil
	}
	for _, expected := range codexHookGroups {
		groups, _ := hooks[expected.eventType].([]interface{})
		for _, candidate := range groups {
			if windowsCodexMachineGroupMatches(candidate, expected, opts) {
				return true, nil
			}
		}
	}
	return false, nil
}

func removeWindowsCodexRequirementsOwnedChanges(
	current []byte,
	baseline []byte,
	opts WindowsCodexMachineRequirementsOptions,
) ([]byte, bool, error) {
	cfg, err := parseWindowsCodexRequirements(current)
	if err != nil {
		return nil, false, fmt.Errorf("parse current Codex requirements: %w", err)
	}
	base, err := parseWindowsCodexRequirements(baseline)
	if err != nil {
		return nil, false, fmt.Errorf("parse stored Codex requirements preimage: %w", err)
	}

	hooks, cfgHooks := cfg["hooks"].(map[string]interface{})
	baseHooks, baseHadHooks := base["hooks"].(map[string]interface{})
	if cfgHooks {
		for _, expected := range codexHookGroups {
			groups, _ := hooks[expected.eventType].([]interface{})
			baselineGroups, _ := baseHooks[expected.eventType].([]interface{})
			baselineCount := 0
			for _, candidate := range baselineGroups {
				if windowsCodexMachineGroupMatches(candidate, expected, opts) {
					baselineCount++
				}
			}
			currentCount := 0
			for _, candidate := range groups {
				if windowsCodexMachineGroupMatches(candidate, expected, opts) {
					currentCount++
				}
			}
			removeCount := currentCount - baselineCount
			if removeCount <= 0 {
				continue
			}
			filtered := make([]interface{}, 0, len(groups)-removeCount)
			for index := len(groups) - 1; index >= 0; index-- {
				candidate := groups[index]
				if removeCount > 0 && windowsCodexMachineGroupMatches(candidate, expected, opts) {
					removeCount--
					continue
				}
				filtered = append(filtered, candidate)
			}
			for left, right := 0, len(filtered)-1; left < right; left, right = left+1, right-1 {
				filtered[left], filtered[right] = filtered[right], filtered[left]
			}
			if len(filtered) == 0 {
				delete(hooks, expected.eventType)
			} else {
				hooks[expected.eventType] = filtered
			}
		}

		// The isolation booleans and managed directory are shared prerequisites
		// for every managed hook. If an administrator added unrelated groups
		// after DefenseClaw installed, transferring those shared keys to the
		// surviving configuration is safer than silently disabling the groups.
		// A surviving reference to our managed directory is counted below and
		// keeps SafeToRemoveBinary false until an administrator explicitly
		// rehomes those hooks.
		if !windowsCodexHooksHaveManagedEntries(hooks) {
			_, baselineManagedDir := baseHooks["windows_managed_dir"]
			if !baseHadHooks || !baselineManagedDir {
				if value, ok := hooks["windows_managed_dir"].(string); ok &&
					sameWindowsCodexMachinePath(value, opts.ManagedDir) {
					delete(hooks, "windows_managed_dir")
				}
			}
		}
		if len(hooks) == 0 && !baseHadHooks {
			delete(cfg, "hooks")
		} else {
			cfg["hooks"] = hooks
		}
	}

	remainingManagedHooks := windowsCodexHooksHaveManagedEntries(hooks)
	if !remainingManagedHooks {
		if _, baselineSet := base["allow_managed_hooks_only"]; !baselineSet {
			if value, ok := cfg["allow_managed_hooks_only"].(bool); ok && value {
				delete(cfg, "allow_managed_hooks_only")
			}
		}

		features, cfgFeatures := cfg["features"].(map[string]interface{})
		baseFeatures, baseHadFeatures := base["features"].(map[string]interface{})
		if cfgFeatures {
			_, baselineSet := baseFeatures["hooks"]
			if !baseHadFeatures || !baselineSet {
				if value, ok := features["hooks"].(bool); ok && value {
					delete(features, "hooks")
				}
			}
			if len(features) == 0 && !baseHadFeatures {
				delete(cfg, "features")
			} else {
				cfg["features"] = features
			}
		}
	}

	rendered, err := toml.Marshal(cfg)
	if err != nil {
		return nil, false, fmt.Errorf("marshal surgically cleaned Codex requirements: %w", err)
	}
	if len(rendered) > windowsCodexMachineRequirementsLimit {
		return nil, false, fmt.Errorf(
			"surgically cleaned Codex requirements exceed %d bytes",
			windowsCodexMachineRequirementsLimit,
		)
	}
	return rendered, !bytes.Equal(current, rendered), nil
}

func windowsCodexHooksHaveManagedEntries(hooks map[string]interface{}) bool {
	for key, raw := range hooks {
		if key == "windows_managed_dir" || key == "state" {
			continue
		}
		switch value := raw.(type) {
		case []interface{}:
			if len(value) > 0 {
				return true
			}
		case nil:
			continue
		default:
			// Unknown hook keys are administrator-owned. Treat them as live
			// rather than deleting shared isolation controls underneath them.
			return true
		}
	}
	return false
}

func windowsCodexOwnedPathReferenceCount(
	raw []byte,
	opts WindowsCodexMachineRequirementsOptions,
) (int, error) {
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		return 0, fmt.Errorf("parse Codex requirements for owned path references: %w", err)
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return 0, nil
	}
	needles := make([]string, 0, 4)
	for _, path := range []string{opts.ManagedDir, opts.HookBinary} {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		canonical := strings.ToLower(filepath.Clean(path))
		needles = append(needles, canonical, strings.ReplaceAll(canonical, `\`, `/`))
	}
	return windowsCodexCountOwnedPathReferences(hooks, needles), nil
}

func windowsCodexCountOwnedPathReferences(value interface{}, needles []string) int {
	switch typed := value.(type) {
	case string:
		candidate := strings.ToLower(typed)
		candidateSlash := strings.ReplaceAll(candidate, `\`, `/`)
		for _, needle := range needles {
			if strings.Contains(candidate, needle) || strings.Contains(candidateSlash, needle) {
				return 1
			}
		}
	case []interface{}:
		total := 0
		for _, item := range typed {
			total += windowsCodexCountOwnedPathReferences(item, needles)
		}
		return total
	case map[string]interface{}:
		total := 0
		for _, item := range typed {
			total += windowsCodexCountOwnedPathReferences(item, needles)
		}
		return total
	}
	return 0
}

func windowsCodexMachineSecurityComplete(opts WindowsCodexMachineRequirementsOptions) bool {
	return opts.EnterpriseTargetEnabled &&
		(!opts.ClaudeTargetEnabled || opts.ClaudeEffectivePolicyVerified)
}

// validateWindowsCodexMachinePrerequisites is the centralized compatibility
// hook for lifecycle preconditions. Application control is optional posture,
// and Claude's effective-policy proof is established after initial policy
// publication, so neither blocks a Codex policy mutation here.
func validateWindowsCodexMachinePrerequisites(opts WindowsCodexMachineRequirementsOptions) error {
	return nil
}

func marshalWindowsCodexMachineOwnership(state windowsCodexMachineOwnership) ([]byte, error) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > windowsCodexMachineOwnershipLimit {
		return nil, fmt.Errorf("Codex requirements ownership exceeds %d bytes", windowsCodexMachineOwnershipLimit)
	}
	return data, nil
}

func parseWindowsCodexMachineOwnership(data []byte) (windowsCodexMachineOwnership, error) {
	var state windowsCodexMachineOwnership
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return state, errors.New("ownership state contains trailing JSON")
		}
		return state, err
	}
	return state, nil
}
