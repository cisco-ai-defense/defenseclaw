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
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
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
	// not carry both, so an unbound command never reaches the gateway. Both
	// Windows profiles set it (WindowsCodexManagedHookContract).
	HookContractID string
	// SecureClient is set for the Secure Client profile, which keeps its
	// earlier reconcile and adoption of hooks.windows_managed_dir: a stale
	// directory is overwritten outside strict trust mode, and adoption strips
	// the current directory with the current groups. Secure Client is out of
	// scope for GAP-0015 and GAP-0022; every other caller gets their fixes.
	SecureClient bool
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
	// reclaimStaleManagedDir overwrites a managed directory that names
	// another install instead of refusing it (Secure Client only, as before
	// GAP-0015); TrustStrictAncestors restores the refusal.
	reclaimStaleManagedDir bool
	// owned, when set, recognizes a DefenseClaw group of any release that
	// is not the exact one under hooks.<event>, so reconcile replaces it
	// instead of adding the exact group next to it.
	owned func(event string, raw interface{}) bool
}

// windowsCodexBoundManagedHookCommand is the standalone command of one
// managed group. It names the group's event and the hook contract, which
// the hook requires, and starts the GUI-subsystem launcher directly through
// the system cmd.exe (windowsCmdDirectHookCommand): the PowerShell bridge
// releases up to 1.0.4 wrote started a second Windows PowerShell on every
// call, which under load used up the hook's answer budget (GAP-1908). A
// launcher path the direct form cannot carry keeps the bridge.
func windowsCodexBoundManagedHookCommand(hookBinary, event, contractID string) string {
	if command, ok := windowsCmdDirectHookCommand(hookBinary, windowsCodexBoundManagedHookArguments(event, contractID)); ok {
		return command
	}
	return bridgeWindowsCodexBoundManagedHookCommand(hookBinary, event, contractID)
}

func windowsCodexBoundManagedHookArguments(event, contractID string) []string {
	return []string{"hook", "--connector", "codex", "--enterprise-managed", "--event", event, "--hook-contract", contractID}
}

// bridgeWindowsCodexBoundManagedHookCommand is the bound managed command
// releases 1.0.1 to 1.0.4 wrote for every launcher path: the encoded system
// PowerShell bridge that starts the GUI-subsystem launcher through the
// awaited Process.Start statements (windowsAwaitedHookStatements); the
// PowerShell call operator does not wait for a GUI-subsystem process, so its
// exit code and stdout would never reach Codex. It is still rendered for a
// launcher path windowsCmdDirectHookCommand cannot carry, and reconcile and
// removal own it (windowsCodexRenderedHookCommand) while those releases are
// upgrade sources.
func bridgeWindowsCodexBoundManagedHookCommand(hookBinary, event, contractID string) string {
	arguments := windowsCodexBoundManagedHookArguments(event, contractID)
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

// windowsCodexMachineGroups is the matrix a Windows machine requirements
// file publishes for commands bound to hookContractID: the ten events every
// supported Codex release accepts, with the compact SessionStart source on
// the contracts that certify it, as per-user setup registers it. The older
// matcher left a compact-source SessionStart unhooked, so it never reached a
// block on managed Windows.
func windowsCodexMachineGroups(hookContractID string) []codexHookGroup {
	groups := append([]codexHookGroup(nil), codexHookGroups...)
	if codexContractCertifiesCompactSessionStart(strings.TrimSpace(hookContractID)) {
		for index := range groups {
			if groups[index].eventType == "SessionStart" {
				groups[index].matcher = codexCompactSessionStartMatcher
			}
		}
	}
	return groups
}

// windowsCodexMachineProfileGroups is the matrix opts publishes. Secure
// Client keeps its earlier matrix (out of scope for this release).
func windowsCodexMachineProfileGroups(opts WindowsCodexMachineRequirementsOptions) []codexHookGroup {
	if opts.SecureClient {
		return codexHookGroups
	}
	return windowsCodexMachineGroups(opts.HookContractID)
}

func windowsCodexMachineLayout(opts WindowsCodexMachineRequirementsOptions) codexMachineRequirementsLayout {
	layout := codexMachineRequirementsLayout{
		managedDirKey:          "windows_managed_dir",
		managedDir:             opts.ManagedDir,
		samePath:               sameWindowsCodexMachinePath,
		groups:                 windowsCodexMachineProfileGroups(opts),
		reclaimStaleManagedDir: opts.SecureClient,
		handler: func(group codexHookGroup) map[string]interface{} {
			return windowsCodexMachineHandler(windowsCodexManagedHookCommandFor(opts, group.eventType), group.timeout)
		},
	}
	if strings.TrimSpace(opts.HookContractID) != "" {
		// Standalone only; Secure Client keeps its exact-group merge.
		layout.owned = func(event string, raw interface{}) bool {
			return windowsCodexOwnedHookGroup(raw, event, opts.HookBinary)
		}
	}
	return layout
}

// windowsCodexOwnedHookGroup reports whether raw, listed under
// hooks.<event>, is a DefenseClaw managed group of any release: the complete
// group DefenseClaw renders for event (windowsCodexRenderedGroupShapes: its
// matcher, one command handler with its timeout and no other key) around a
// command that is, byte for byte, a managed Codex command DefenseClaw
// renders for hookBinary and event (windowsCodexRenderedHookCommand). An
// upgrade from 1.0.0 kept the 1.0.0 group (its Start-Process form) next to
// the current one, so every Codex event ran, was audited and was judged
// twice (GAP-1025). Any other group is the administrator's, even one that
// runs DefenseClaw's own command: a script that only names hookBinary or the
// managed flags (in diagnostic text, with an extra statement or an extra
// argument), or DefenseClaw's group edited with another matcher, timeout or
// handler key, or moved under another event. Reconcile, removal, the
// stale-layout strip and inference leave it alone, and its reference to the
// launcher keeps the binary removal unsafe.
func windowsCodexOwnedHookGroup(raw interface{}, event, hookBinary string) bool {
	group, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	handlers, ok := group["hooks"].([]interface{})
	if !ok || len(handlers) != 1 {
		return false
	}
	handler, ok := handlers[0].(map[string]interface{})
	if !ok {
		return false
	}
	command, _ := handler["command"].(string)
	boundEvent, contract, ok := windowsCodexRenderedHookCommand(command, hookBinary)
	if !ok || boundEvent != "" && boundEvent != event {
		return false
	}
	for _, shape := range windowsCodexRenderedGroupShapes(event, contract) {
		if windowsCodexMachineGroupHasCommand(raw, shape, command) {
			return true
		}
	}
	return false
}

// windowsCodexRenderedGroupShapes is every group shape (matcher and timeout)
// a release renders for event with commands bound to contractID (empty for
// the unbound command): the shared matrix every release and Secure Client
// write, and the compact SessionStart matcher of the contracts that certify
// it (windowsCodexMachineGroups). An event no release hooks has none.
func windowsCodexRenderedGroupShapes(event, contractID string) []codexHookGroup {
	var shapes []codexHookGroup
	for _, group := range append(append([]codexHookGroup(nil), codexHookGroups...), windowsCodexMachineGroups(contractID)...) {
		if group.eventType == event && !slices.Contains(shapes, group) {
			shapes = append(shapes, group)
		}
	}
	return shapes
}

// windowsCodexBoundArgumentsPattern finds the event and hook contract in the
// decoded script of a bound managed Codex command: both the awaited and the
// Start-Process forms quote the launcher's argument list.
var windowsCodexBoundArgumentsPattern = lazyregexp.New(
	`'--event'[ ,]'((?:[^']|'')*)'[ ,]'--hook-contract'[ ,]'((?:[^']|'')*)'`,
)

// windowsCodexDirectBoundArgumentsPattern finds the event and hook contract
// at the end of a direct bound managed command (windowsCmdDirectHookCommand).
var windowsCodexDirectBoundArgumentsPattern = lazyregexp.New(
	` --event ([A-Za-z0-9._-]+) --hook-contract ([A-Za-z0-9._-]+)$`,
)

// windowsCodexRenderedHookCommand reports whether command is exactly a
// managed Codex command DefenseClaw renders for hookBinary, and for which
// event and hook contract: the unbound form (windowsCodexManagedHookCommand,
// no event or contract), or the bound form for the event and hook contract
// the command names, current (windowsCodexBoundManagedHookCommand, direct or
// bridge), the bridge of releases 1.0.1 to 1.0.4
// (bridgeWindowsCodexBoundManagedHookCommand), or of the
// 1.0.0 certification builds
// (legacyStartProcessWindowsCodexBoundManagedHookCommand). The event and the
// contract are read from the script only to render the candidate; ownership
// is the byte-for-byte equality, so no script that merely mentions the
// launcher is DefenseClaw's.
func windowsCodexRenderedHookCommand(command, hookBinary string) (event, contract string, ok bool) {
	if strings.TrimSpace(hookBinary) == "" || strings.TrimSpace(command) == "" {
		return "", "", false
	}
	if command == windowsCodexManagedHookCommand(hookBinary) {
		return "", "", true
	}
	if match := windowsCodexDirectBoundArgumentsPattern.FindStringSubmatch(command); match != nil &&
		command == windowsCodexBoundManagedHookCommand(hookBinary, match[1], match[2]) {
		return match[1], match[2], true
	}
	prefix := windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand "
	if !strings.HasPrefix(command, prefix) {
		return "", "", false
	}
	script, decoded := powershellDecodedCommand(strings.TrimPrefix(command, prefix))
	if !decoded {
		return "", "", false
	}
	for _, match := range windowsCodexBoundArgumentsPattern.FindAllStringSubmatch(script, -1) {
		event := strings.ReplaceAll(match[1], "''", "'")
		contract := strings.ReplaceAll(match[2], "''", "'")
		if command == bridgeWindowsCodexBoundManagedHookCommand(hookBinary, event, contract) ||
			command == legacyStartProcessWindowsCodexBoundManagedHookCommand(hookBinary, event, contract) {
			return event, contract, true
		}
	}
	return "", "", false
}

// legacyStartProcessWindowsCodexBoundManagedHookCommand reconstructs the
// bound managed command of the 1.0.0 certification builds, which started the
// launcher with Start-Process -Wait -PassThru before the awaited
// Process.Start statements (windowsAwaitedHookStatements). It is never
// generated: reconcile replaces it and a standalone removal takes it
// (GAP-1025). It serves upgrades from those 1.0.0 builds; remove it with
// the 1.0.x upgrade path.
func legacyStartProcessWindowsCodexBoundManagedHookCommand(hookBinary, event, contractID string) string {
	arguments := []string{"hook", "--connector", "codex", "--enterprise-managed", "--event", event, "--hook-contract", contractID}
	quoted := make([]string, len(arguments))
	for i, argument := range arguments {
		quoted[i] = powershellQuoteLiteral(argument)
	}
	script := strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		"$env:NoDefaultCurrentDirectoryInExePath='1'",
		"$hookProcess=Microsoft.PowerShell.Management\\Start-Process -FilePath " + powershellQuoteLiteral(hookBinary) +
			" -ArgumentList @(" + strings.Join(quoted, ",") + ") -NoNewWindow -Wait -PassThru",
		"exit $hookProcess.ExitCode",
	}, "; ")
	return windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + powershellEncodedCommand(script)
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
		// Another directory is the administrator's (or a prior install's
		// that adoption could not prove DefenseClaw's): refuse, never
		// overwrite it (GAP-0015). windowsCodexAdoptRequirements strips a
		// prior DefenseClaw layout's directory before reconcile runs.
		if !l.samePath(value, l.managedDir) {
			if !l.reclaimStaleManagedDir || managed.TrustStrictAncestors() {
				return fmt.Errorf(
					"hooks.%s=%q conflicts with protected managed directory %q",
					l.managedDirKey,
					value,
					l.managedDir,
				)
			}
			// Secure Client keeps its earlier bulldoze: a prior unsigned
			// certification install at a scoped path left the managed
			// directory pointing at its (now stale) bin directory. The
			// statement below overwrites it with the current install's
			// canonical directory; log it so a DART review can find the
			// recovery.
			fmt.Fprintf(os.Stderr,
				"[enterprise-hooks] reclaiming stale Codex hooks.%s = %q, overwriting with current install's canonical ManagedDir %q\n",
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
		kept := groups[:0:0]
		for _, candidate := range groups {
			if l.groupMatches(candidate, expected) {
				if found && l.owned != nil {
					continue
				}
				found = true
			} else if l.owned != nil && l.owned(expected.eventType, candidate) {
				continue
			}
			kept = append(kept, candidate)
		}
		if !found {
			kept = append(kept, l.expectedGroup(expected))
		}
		hooks[expected.eventType] = kept
	}
	cfg["hooks"] = hooks
	return nil
}

// eventsWithExactGroup reports the managed events whose list in cfg already
// holds the exact group this layout renders for them.
func (l codexMachineRequirementsLayout) eventsWithExactGroup(cfg map[string]interface{}) map[string]bool {
	exact := map[string]bool{}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	for _, expected := range l.groups {
		groups, _ := hooks[expected.eventType].([]interface{})
		for _, candidate := range groups {
			if l.groupMatches(candidate, expected) {
				exact[expected.eventType] = true
				break
			}
		}
	}
	return exact
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
	if err := parseCodexTOML(raw, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// reconcileWindowsCodexRequirements merges the managed hook matrix opts
// publishes into raw. published reports that raw is, byte for byte, the file
// DefenseClaw last published (the ownership record's postimage), so nobody
// has edited it since.
//
// This install's own command in the SessionStart shape only an earlier
// release renders (windowsCodexEditedCurrentGroup) is either that release's
// group or this install's group as an administrator edited it: the two are
// byte for byte the same. It is replaced, as the earlier release's group,
// only when published proves DefenseClaw wrote it and the file holds no exact
// group of this install for that event (an upgrade from 1.0.2 or 1.0.3 that
// nobody edited since). Every other such group is kept and the exact group is
// added beside it, so a repair never deletes what may be an administrator's
// edit. A publication of this install that already kept it holds the exact
// group, so later repairs keep it too. Uninstall takes it with the rest of
// this install's groups (removeWindowsCodexOwnedGroups, GAP-0907): it runs
// the hook binary the uninstall deletes.
func reconcileWindowsCodexRequirements(
	raw []byte,
	opts WindowsCodexMachineRequirementsOptions,
	published bool,
) ([]byte, bool, error) {
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		return nil, false, fmt.Errorf("parse Codex requirements: %w", err)
	}
	layout := windowsCodexMachineLayout(opts)
	if owned := layout.owned; owned != nil {
		exact := layout.eventsWithExactGroup(cfg)
		layout.owned = func(event string, group interface{}) bool {
			if !owned(event, group) {
				return false
			}
			return !windowsCodexEditedCurrentGroup(group, event, opts) || published && !exact[event]
		}
	}
	if err := layout.reconcile(cfg); err != nil {
		return nil, false, err
	}

	rendered, err := toml.Marshal(cfg)
	if err != nil {
		return nil, false, fmt.Errorf("marshal Codex requirements: %w", err)
	}
	rendered = retainCodexTOMLBOM(raw, rendered)
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
	for _, expected := range windowsCodexMachineProfileGroups(opts) {
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
		for _, expected := range windowsCodexMachineProfileGroups(opts) {
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
		// A standalone removal also takes DefenseClaw's groups of any
		// release or hook contract (windowsCodexOwnedHookGroup), whatever
		// the baseline holds: a group that runs this install's hook binary
		// in a shape a DefenseClaw release renders is DefenseClaw's, and one
		// left behind would run a removed binary and strand the uninstall
		// on its reference (GAP-0907). That includes this install's command
		// in the SessionStart shape of 1.0.2 and 1.0.3, whether or not the
		// recorded baseline holds it.
		if windowsCodexOwnedGroupsRecognized(opts) {
			removeWindowsCodexOwnedGroups(hooks, opts)
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
			// With no hook left, a managed directory that names this
			// install's own directory serves nothing and points into the
			// tree the removal deletes: a standalone removal takes it even
			// when the baseline holds it (GAP-0907).
			if !baseHadHooks || !baselineManagedDir || windowsCodexOwnedGroupsRecognized(opts) {
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
	rendered = retainCodexTOMLBOM(current, rendered)
	if len(rendered) > windowsCodexMachineRequirementsLimit {
		return nil, false, fmt.Errorf(
			"surgically cleaned Codex requirements exceed %d bytes",
			windowsCodexMachineRequirementsLimit,
		)
	}
	return rendered, !bytes.Equal(current, rendered), nil
}

// windowsCodexEditedCurrentGroup reports whether raw, listed under
// hooks.<event>, runs exactly the command this install renders for event
// but is not the group this install renders there. Another release renders
// that shape (the SessionStart matcher before the compact source), so the
// shape alone does not make it DefenseClaw's: it is what an administrator
// who edits this install's group gets (the compact source cut from the
// matcher). Reconcile replaces it only in a file nobody edited since
// DefenseClaw published it that holds no exact group of this install (the
// earlier release's own file, reconcileWindowsCodexRequirements). A
// standalone removal takes it as DefenseClaw's: it runs the binary the
// removal deletes (GAP-0907).
func windowsCodexEditedCurrentGroup(raw interface{}, event string, opts WindowsCodexMachineRequirementsOptions) bool {
	command := windowsCodexManagedHookCommandFor(opts, event)
	for _, shape := range windowsCodexMachineProfileGroups(opts) {
		if shape.eventType == event && windowsCodexMachineGroupHasCommand(raw, shape, command) {
			return false
		}
	}
	group, _ := raw.(map[string]interface{})
	handlers, _ := group["hooks"].([]interface{})
	if len(handlers) != 1 {
		return false
	}
	handler, _ := handlers[0].(map[string]interface{})
	got, _ := handler["command"].(string)
	return got == command
}

// windowsCodexOwnedGroupsRecognized reports whether opts recognizes
// DefenseClaw's managed groups of any release by their hook binary: a
// standalone layout (bound to a hook contract), as reconcile does.
func windowsCodexOwnedGroupsRecognized(opts WindowsCodexMachineRequirementsOptions) bool {
	return strings.TrimSpace(opts.HookContractID) != "" && strings.TrimSpace(opts.HookBinary) != ""
}

// removeWindowsCodexOwnedGroups drops every DefenseClaw managed group of any
// release (windowsCodexOwnedHookGroup) from each event list of hooks.
func removeWindowsCodexOwnedGroups(hooks map[string]interface{}, opts WindowsCodexMachineRequirementsOptions) {
	for key, raw := range hooks {
		groups, ok := raw.([]interface{})
		if !ok || key == "windows_managed_dir" || key == "state" {
			continue
		}
		kept := make([]interface{}, 0, len(groups))
		for _, group := range groups {
			if !windowsCodexOwnedHookGroup(group, key, opts.HookBinary) {
				kept = append(kept, group)
			}
		}
		if len(kept) == len(groups) {
			continue
		}
		if len(kept) == 0 {
			delete(hooks, key)
		} else {
			hooks[key] = kept
		}
	}
}

// windowsCodexRemovalCandidate computes the requirements a removal publishes
// from the live file and the protected ownership record: the recorded
// preimage when the file is still DefenseClaw's exact publication, cleaned
// of what an earlier release left in it, or else the live file with
// DefenseClaw's changes removed surgically. candidateExists false deletes
// the file.
func windowsCodexRemovalCandidate(
	current []byte,
	currentExists bool,
	state windowsCodexMachineOwnership,
	opts WindowsCodexMachineRequirementsOptions,
) (candidate []byte, candidateExists, changed bool, disposition string, err error) {
	exactPostimage := currentExists && windowsCodexMachineHash(current) == state.PostimageSHA256
	// A preimage an earlier release recorded with its own groups (or
	// their managed directory alone) is DefenseClaw's in those parts:
	// restoring it verbatim would strand the uninstall on them
	// (GAP-0907, GAP-1456), so it is cleaned as a surgical removal is.
	preimageLeftovers := false
	if exactPostimage && state.PreimageExisted {
		if preimageLeftovers, err = windowsCodexRequirementsHoldOwnedLeftovers(state.Preimage, opts); err != nil {
			return nil, false, false, "", fmt.Errorf("inspect the recorded Codex requirements preimage: %w", err)
		}
	}
	switch {
	case exactPostimage && state.PreimageExisted && preimageLeftovers:
		cleaned, _, cleanErr := removeWindowsCodexRequirementsOwnedChanges(state.Preimage, state.Preimage, opts)
		if cleanErr != nil {
			return nil, false, false, "", cleanErr
		}
		return cleaned, true, !bytes.Equal(current, cleaned), "restored_preimage", nil
	case exactPostimage && state.PreimageExisted:
		preimage := append([]byte(nil), state.Preimage...)
		return preimage, true, !bytes.Equal(current, state.Preimage), "restored_preimage", nil
	case exactPostimage:
		return nil, false, currentExists, "restored_preimage", nil
	default:
		cleaned, cleanChanged, cleanErr := removeWindowsCodexRequirementsOwnedChanges(current, state.Preimage, opts)
		if cleanErr != nil {
			return nil, false, false, "", cleanErr
		}
		if len(bytes.TrimSpace(cleaned)) == 0 && !state.PreimageExisted {
			return nil, false, cleanChanged, "surgical_preservation", nil
		}
		return cleaned, true, cleanChanged, "surgical_preservation", nil
	}
}

// windowsCodexRequirementsHoldOwnedLeftovers reports whether raw still holds
// what a standalone removal takes: a DefenseClaw managed group of any
// release, or, with no hook left, a managed directory that names this
// install's own directory.
func windowsCodexRequirementsHoldOwnedLeftovers(raw []byte, opts WindowsCodexMachineRequirementsOptions) (bool, error) {
	if !windowsCodexOwnedGroupsRecognized(opts) {
		return false, nil
	}
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		return false, err
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return false, nil
	}
	for key, value := range hooks {
		groups, ok := value.([]interface{})
		if !ok || key == "windows_managed_dir" || key == "state" {
			continue
		}
		for _, group := range groups {
			if windowsCodexOwnedHookGroup(group, key, opts.HookBinary) {
				return true, nil
			}
		}
	}
	dir, ok := hooks["windows_managed_dir"].(string)
	return ok && !windowsCodexHooksHaveManagedEntries(hooks) && sameWindowsCodexMachinePath(dir, opts.ManagedDir), nil
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

// EnableManifestTarget records one enabled targets.yaml row. Only Claude
// Code, Codex and Cursor have a Windows machine policy, so only their rows
// count toward security_complete. A deployment whose only rows are other
// connectors (Copilot, OpenCode, the per-user connectors) is not
// security-complete, as DefenseClawEnterprise.psm1 computes it; counting any
// enabled row made status and verify fail with "aggregate security result
// disagrees with protected evidence" (GAP-0238).
func (o *WindowsCodexMachineRequirementsOptions) EnableManifestTarget(connectorName string) {
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "claudecode":
		o.ClaudeTargetEnabled = true
	case "codex":
		o.CodexTargetEnabled = true
	case "cursor":
		o.CursorTargetEnabled = true
	}
}

func windowsCodexMachineSecurityComplete(opts WindowsCodexMachineRequirementsOptions) bool {
	return (opts.ClaudeTargetEnabled || opts.CodexTargetEnabled || opts.CursorTargetEnabled) &&
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
		return nil, fmt.Errorf("Codex requirements ownership exceeds %d bytes", windowsCodexMachineOwnershipLimit) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
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

// windowsCodexAdoption is the result of windowsCodexAdoptRequirements.
type windowsCodexAdoption struct {
	// base is the requirements document reconcile starts from: the current
	// file without the hook groups and managed directory of a discarded
	// prior layout, so the stale DefenseClaw groups do not survive next to
	// the current ones.
	base []byte
	// preimage and preimageExisted are what the fresh ownership record
	// stores; uninstall restores (or surgically reduces to) this preimage.
	preimage        []byte
	preimageExisted bool
}

// windowsCodexAdoptRequirements prepares reconcile's adoption of a
// requirements document whose ownership record is absent, unparseable, or
// belongs to another protected layout. discarded is that other layout's
// parseable record, or nil when there is none.
//
// The preimage is the current document without DefenseClaw's changes:
//   - groups that run the discarded layout's hook binary, and its
//     windows_managed_dir, are removed (from the live base too);
//   - with no record of it, a prior layout the file itself proves
//     DefenseClaw's (windowsCodexUnrecordedStaleLayout) is removed the same
//     way; an administrator's windows_managed_dir is left for reconcile to
//     refuse;
//   - groups that run the current hook binary, in any release's command form,
//     are removed, and the current windows_managed_dir with them unless
//     administrator hook entries that need it survive;
//   - allow_managed_hooks_only and features.hooks are DefenseClaw's (every
//     reconcile pins them) unless the discarded record's trustworthy preimage
//     of this same requirements file shows they predate DefenseClaw. Without
//     that evidence they stay only while administrator hook entries that
//     need them survive (removeWindowsCodexRequirementsOwnedChanges).
//
// A document with no DefenseClaw evidence at all (fresh install) is its own
// preimage. preimageExisted reports whether anything is left, so a later
// removal deletes a file DefenseClaw created (GAP-0938).
func windowsCodexAdoptRequirements(
	current []byte,
	currentExisted bool,
	discarded *windowsCodexMachineOwnership,
	opts WindowsCodexMachineRequirementsOptions,
) (windowsCodexAdoption, error) {
	adoption := windowsCodexAdoption{base: current}
	evidence := discarded != nil
	if discarded != nil {
		staleBinary := strings.TrimSpace(discarded.HookBinary)
		if staleBinary != "" && sameWindowsCodexMachinePath(staleBinary, opts.HookBinary) {
			staleBinary = ""
		}
		staleDir := strings.TrimSpace(discarded.ManagedDir)
		if staleDir != "" && sameWindowsCodexMachinePath(staleDir, opts.ManagedDir) {
			staleDir = ""
		}
		base, stripped, err := stripWindowsCodexLayout(current, staleBinary, staleDir)
		if err != nil {
			return windowsCodexAdoption{}, fmt.Errorf("strip prior Codex managed layout: %w", err)
		}
		if stripped {
			adoption.base = base
		}
	}
	if staleDir, staleBinary := windowsCodexUnrecordedStaleLayout(adoption.base, opts); !opts.SecureClient && staleDir != "" {
		base, stripped, err := stripWindowsCodexLayout(adoption.base, staleBinary, staleDir)
		if err != nil {
			return windowsCodexAdoption{}, fmt.Errorf("strip unrecorded prior Codex managed layout: %w", err)
		}
		if stripped {
			adoption.base = base
			evidence = true
		}
	}
	contains, err := windowsCodexRequirementsContainExactManagedHook(adoption.base, opts)
	if err != nil {
		return windowsCodexAdoption{}, fmt.Errorf("detect adopted Codex managed hooks: %w", err)
	}
	// Only the current launcher's groups are DefenseClaw's evidence. A
	// windows_managed_dir equal to ManagedDir with no DefenseClaw group is the
	// administrator's and stays in the verbatim preimage; when DefenseClaw
	// groups are present, removeWindowsCodexRequirementsOwnedChanges decides
	// whether the directory goes with them (GAP-0022). Secure Client keeps
	// stripping the current directory here, as before.
	currentDir := ""
	if opts.SecureClient {
		currentDir = opts.ManagedDir
	}
	// This install's own command in a shape only an earlier release renders
	// (windowsCodexEditedCurrentGroup) leaves the preimage too: uninstall
	// removes it with the rest of this install's groups (GAP-0907), so a
	// restored preimage must not bring it back (GAP-1767).
	withoutCurrent, strippedCurrent, err := stripWindowsCodexLayout(adoption.base, opts.HookBinary, currentDir)
	if err != nil {
		return windowsCodexAdoption{}, fmt.Errorf("strip current Codex managed layout: %w", err)
	}
	if !evidence && !contains && !strippedCurrent {
		adoption.preimage = append([]byte(nil), current...)
		adoption.preimageExisted = currentExisted
		return adoption, nil
	}
	var baseline []byte
	if windowsCodexDiscardedPreimageTrusted(discarded, opts) {
		if baseline, err = windowsCodexAdoptPreimageBaseline(discarded.Preimage); err != nil {
			return windowsCodexAdoption{}, err
		}
	}
	cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(withoutCurrent, baseline, opts)
	if err != nil {
		return windowsCodexAdoption{}, err
	}
	left, err := parseWindowsCodexRequirements(cleaned)
	if err != nil {
		return windowsCodexAdoption{}, err
	}
	if len(left) != 0 {
		adoption.preimage = cleaned
		adoption.preimageExisted = true
	}
	return adoption, nil
}

// windowsCodexUnrecordedStaleLayout names a prior DefenseClaw layout that
// requirements prove with no ownership record: hooks.windows_managed_dir is
// another directory and at least one group runs that directory's DefenseClaw
// hook launcher as the managed Codex hook (a purge that ran without the state
// root left a scoped install's layout behind). Any other directory is the
// administrator's; reconcile refuses it and nothing here overwrites it
// (GAP-0015). Strict trust mode adopts nothing on inference.
func windowsCodexUnrecordedStaleLayout(raw []byte, opts WindowsCodexMachineRequirementsOptions) (string, string) {
	if managed.TrustStrictAncestors() {
		return "", ""
	}
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		return "", ""
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	dir, _ := hooks["windows_managed_dir"].(string)
	if strings.TrimSpace(dir) == "" || sameWindowsCodexMachinePath(dir, opts.ManagedDir) {
		return "", ""
	}
	launcher := opts.HookBinary[strings.LastIndexAny(opts.HookBinary, `\/`)+1:]
	if strings.TrimSpace(launcher) == "" {
		return "", ""
	}
	staleBinary := strings.TrimRight(dir, `\/`) + `\` + launcher
	for key, rawGroups := range hooks {
		groups, _ := rawGroups.([]interface{})
		for _, group := range groups {
			if windowsCodexOwnedHookGroup(group, key, staleBinary) {
				return dir, staleBinary
			}
		}
	}
	return "", ""
}

// windowsCodexDiscardedPreimageTrusted reports whether a discarded ownership
// record's preimage is evidence about this requirements file: same path, a
// hash that matches the stored bytes, and parseable TOML.
func windowsCodexDiscardedPreimageTrusted(
	discarded *windowsCodexMachineOwnership,
	opts WindowsCodexMachineRequirementsOptions,
) bool {
	if discarded == nil || !discarded.PreimageExisted ||
		!sameWindowsCodexMachinePath(discarded.RequirementsPath, opts.RequirementsPath) ||
		discarded.PreimageSHA256 != windowsCodexMachineHash(discarded.Preimage) {
		return false
	}
	_, err := parseWindowsCodexRequirements(discarded.Preimage)
	return err == nil
}

// stripWindowsCodexLayout removes every hook group that runs hookBinary as
// the managed Codex hook (in any release's command form) and a
// windows_managed_dir equal to managedDir. Empty arguments strip nothing of
// that kind. It reports whether anything was removed; the document is
// re-rendered only then.
func stripWindowsCodexLayout(raw []byte, hookBinary, managedDir string) ([]byte, bool, error) {
	if strings.TrimSpace(hookBinary) == "" && strings.TrimSpace(managedDir) == "" {
		return raw, false, nil
	}
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		return nil, false, err
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return raw, false, nil
	}
	stripped := false
	if strings.TrimSpace(managedDir) != "" {
		if value, ok := hooks["windows_managed_dir"].(string); ok && sameWindowsCodexMachinePath(value, managedDir) {
			delete(hooks, "windows_managed_dir")
			stripped = true
		}
	}
	if strings.TrimSpace(hookBinary) != "" {
		for key, rawGroups := range hooks {
			groups, ok := rawGroups.([]interface{})
			if !ok {
				continue
			}
			kept := make([]interface{}, 0, len(groups))
			for _, candidate := range groups {
				if windowsCodexOwnedHookGroup(candidate, key, hookBinary) {
					stripped = true
					continue
				}
				kept = append(kept, candidate)
			}
			if len(kept) == len(groups) {
				continue
			}
			if len(kept) == 0 {
				delete(hooks, key)
			} else {
				hooks[key] = kept
			}
		}
	}
	if !stripped {
		return raw, false, nil
	}
	if len(hooks) == 0 {
		delete(cfg, "hooks")
	} else {
		cfg["hooks"] = hooks
	}
	rendered, err := toml.Marshal(cfg)
	if err != nil {
		return nil, false, fmt.Errorf("marshal Codex requirements without a managed layout: %w", err)
	}
	return retainCodexTOMLBOM(raw, rendered), true, nil
}

// windowsCodexAdoptPreimageBaseline extracts the shared isolation controls
// (allow_managed_hooks_only and features.hooks) from a trusted pre-DefenseClaw
// preimage as a minimal baseline TOML. removeWindowsCodexRequirementsOwnedChanges
// keeps exactly the controls a baseline names, so an uninstall that restores
// the adopted preimage does not delete isolation controls the administrator
// configured before DefenseClaw installed.
func windowsCodexAdoptPreimageBaseline(preimage []byte) ([]byte, error) {
	cfg, err := parseWindowsCodexRequirements(preimage)
	if err != nil {
		return nil, fmt.Errorf("parse Codex requirements for baseline synthesis: %w", err)
	}
	baseline := map[string]interface{}{}
	if value, ok := cfg["allow_managed_hooks_only"]; ok {
		baseline["allow_managed_hooks_only"] = value
	}
	if features, ok := cfg["features"].(map[string]interface{}); ok {
		if hookValue, hookOk := features["hooks"]; hookOk {
			baseline["features"] = map[string]interface{}{"hooks": hookValue}
		}
	}
	if len(baseline) == 0 {
		return nil, nil
	}
	rendered, err := toml.Marshal(baseline)
	if err != nil {
		return nil, fmt.Errorf("marshal Codex adopt baseline: %w", err)
	}
	return rendered, nil
}
