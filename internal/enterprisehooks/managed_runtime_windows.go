// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const WindowsManagedSIDUnregisteredReason = "enterprise_managed_sid_unregistered"

// ErrWindowsManagedSIDUnregistered is wrapped only by resolver failures whose
// cause is that the current SID is absent from the protected target set.
// Classify with errors.Is, never by message text: other errors can carry
// target-owned paths.
var ErrWindowsManagedSIDUnregistered = errors.New(WindowsManagedSIDUnregisteredReason)

// WindowsManagedEnrollmentPendingReason is the standalone hook's refusal of
// an account the machine policy registers that has no managed runtime yet:
// the guardian creates it while the account is signed in.
const WindowsManagedEnrollmentPendingReason = "enterprise_managed_enrollment_pending"

// ErrWindowsManagedRuntimeGenerationPending reports that no managed runtime
// generation is selected for a registered account yet.
var ErrWindowsManagedRuntimeGenerationPending = errors.New("no managed runtime generation is selected for this account yet")

// WindowsManagedHookRuntime is the administrator-authorized runtime selected
// for the current process token. PolicyActive distinguishes a clean
// post-uninstall absence from a damaged or unregistered active global policy.
type WindowsManagedHookRuntime struct {
	Connector          string `json:"connector"`
	DataDir            string `json:"data_dir"`
	PolicyActive       bool   `json:"policy_active"`
	Registered         bool   `json:"registered"`
	GatewayAddr        string `json:"gateway_addr"`
	GatewayServiceName string `json:"gateway_service_name"`
	FailMode           string `json:"fail_mode"`
	ScopedToken        string `json:"-"`
	GenerationID       string `json:"generation_id"`
}

// String deliberately omits ScopedToken so diagnostic formatting cannot
// disclose the per-target gateway credential.
func (r WindowsManagedHookRuntime) String() string {
	return fmt.Sprintf(
		"WindowsManagedHookRuntime{Connector:%q DataDir:%q PolicyActive:%t Registered:%t GatewayAddr:%q GatewayServiceName:%q GenerationID:%q}",
		r.Connector,
		r.DataDir,
		r.PolicyActive,
		r.Registered,
		r.GatewayAddr,
		r.GatewayServiceName,
		r.GenerationID,
	)
}

func (r WindowsManagedHookRuntime) GoString() string { return r.String() }

// ResolveWindowsManagedHookRuntime performs connector-aware machine-policy
// resolution before any target-owned configuration is trusted.
func ResolveWindowsManagedHookRuntime(
	hookExecutable string,
	connectorName string,
) (WindowsManagedHookRuntime, error) {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	switch name {
	case "claudecode":
		return resolveWindowsClaudeManagedHookRuntime(hookExecutable)
	case "codex":
		return resolveWindowsCodexManagedHookRuntime(hookExecutable)
	case "cursor":
		return resolveWindowsCursorManagedHookRuntime(hookExecutable)
	case "copilot", "antigravity", "devin", "hermes", "kiro", "opencode":
		return resolveWindowsPerUserManagedHookRuntime(hookExecutable, name)
	default:
		return WindowsManagedHookRuntime{}, fmt.Errorf(
			"enterprise hooks: unsupported Windows managed connector %q",
			connectorName,
		)
	}
}

func resolveWindowsCursorManagedHookRuntime(
	hookExecutable string,
) (WindowsManagedHookRuntime, error) {
	target, err := resolveWindowsCursorManagedPolicyTarget()
	result := WindowsManagedHookRuntime{
		Connector: "cursor",
		DataDir:   target.dataDir,
	}
	if err != nil {
		return result, err
	}
	if !target.active {
		return result, nil
	}
	result.PolicyActive = true
	if !sameWindowsEnterprisePath(target.hookExecutable, hookExecutable) {
		return result, fmt.Errorf(
			"enterprise hooks: invoking hook executable %s does not match active Cursor policy executable %s",
			hookExecutable,
			target.hookExecutable,
		)
	}
	if !target.registered {
		sid := "<unknown>"
		if target.targetSID != nil {
			sid = target.targetSID.String()
		}
		return result, fmt.Errorf(
			"%w: connector cursor current SID %s is absent from the protected target set",
			ErrWindowsManagedSIDUnregistered,
			sid,
		)
	}
	generation, err := windowsManagedRuntimeGenerationResolve(
		WindowsManagedRuntimeGenerationResolveOptions{
			Connector:               "cursor",
			TargetSID:               target.targetSID.String(),
			DataDir:                 target.dataDir,
			HookExecutable:          hookExecutable,
			MachinePolicyRegistered: true,
		},
	)
	if err != nil {
		return result, err
	}
	result.GatewayAddr = generation.GatewayAddr
	if err := verifyWindowsCursorRuntimeDeliveryMode(target.hookFailMode, generation.FailMode); err != nil {
		return result, err
	}
	result.GatewayServiceName = generation.GatewayServiceName
	result.ScopedToken = generation.ScopedToken()
	result.GenerationID = generation.GenerationID
	result.FailMode = generation.FailMode
	result.Registered = true
	return result, nil
}

func verifyWindowsCursorRuntimeDeliveryMode(adapterMode, generationMode string) error {
	// Legacy singleton adapters had no per-SID mode binding. Reconciliation
	// migrates them without invalidating previously authenticated generations.
	if adapterMode != "" && adapterMode != generationMode {
		return errors.New("enterprise hooks: Cursor adapter mode differs from the authenticated runtime generation")
	}
	return nil
}

func resolveWindowsClaudeManagedHookRuntime(
	hookExecutable string,
) (WindowsManagedHookRuntime, error) {
	target, err := resolveWindowsClaudeManagedPolicyTarget()
	result := WindowsManagedHookRuntime{
		Connector: "claudecode",
		DataDir:   target.dataDir,
	}
	if err != nil {
		return result, err
	}
	if !target.policyExists {
		return result, nil
	}
	result.PolicyActive = true
	gatewayAddr, gatewayErr := connector.NormalizeWindowsManagedGatewayAddr(target.gatewayAddr)
	if gatewayErr != nil || gatewayAddr != target.gatewayAddr {
		return result, errors.New("enterprise hooks: active Claude policy has no valid protected gateway address")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(target.gatewayServiceName); err != nil {
		return result, err
	}
	if !sameWindowsEnterprisePath(target.hookExecutable, hookExecutable) {
		return result, fmt.Errorf(
			"enterprise hooks: invoking hook executable %s does not match active managed policy executable %s",
			hookExecutable,
			target.hookExecutable,
		)
	}
	if !target.registered {
		sid := "<unknown>"
		if target.targetSID != nil {
			sid = target.targetSID.String()
		}
		return result, fmt.Errorf(
			"%w: connector claudecode current SID %s is absent from the protected target set",
			ErrWindowsManagedSIDUnregistered,
			sid,
		)
	}
	generation, err := windowsManagedRuntimeGenerationResolve(
		WindowsManagedRuntimeGenerationResolveOptions{
			Connector:               "claudecode",
			TargetSID:               target.targetSID.String(),
			DataDir:                 target.dataDir,
			HookExecutable:          hookExecutable,
			MachinePolicyRegistered: true,
		},
	)
	if err != nil {
		return result, err
	}
	// The hook consumes the generation gateway identity, not the
	// policy record. Reject a policy whose gateway metadata does not
	// match the resolved generation instead of silently trusting one
	// source. The generation resolver otherwise never compares them.
	if generation.GatewayAddr != target.gatewayAddr ||
		generation.GatewayServiceName != target.gatewayServiceName {
		return result, errors.New(
			"enterprise hooks: Claude managed policy gateway identity does not match the resolved generation",
		)
	}
	result.GatewayAddr = generation.GatewayAddr
	result.GatewayServiceName = generation.GatewayServiceName
	result.ScopedToken = generation.ScopedToken()
	result.GenerationID = generation.GenerationID
	result.FailMode = generation.FailMode
	result.Registered = true
	return result, nil
}

func resolveWindowsCodexManagedHookRuntime(
	hookExecutable string,
) (WindowsManagedHookRuntime, error) {
	result := WindowsManagedHookRuntime{
		Connector: "codex",
	}
	registry, err := connector.ResolveWindowsCodexManagedRuntimeRegistry(hookExecutable)
	if err != nil {
		result.PolicyActive = true
		return result, fmt.Errorf("enterprise hooks: resolve protected Codex runtime state: %w", err)
	}
	if !registry.Active {
		return result, nil
	}
	result.PolicyActive = true
	targets := registry.Targets
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return result, fmt.Errorf("enterprise hooks: resolve current Windows hook SID: %w", err)
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return result, errors.New("enterprise hooks: current Windows hook token has no user SID")
	}
	currentSID := tokenUser.User.Sid
	var selected *connector.WindowsCodexManagedRuntimeTarget
	for index := range targets {
		if strings.EqualFold(targets[index].SID, currentSID.String()) {
			selected = &targets[index]
			break
		}
	}
	if selected == nil {
		return result, fmt.Errorf(
			"%w: connector codex current SID %s is absent from the protected target set",
			ErrWindowsManagedSIDUnregistered,
			currentSID,
		)
	}
	result.DataDir = selected.DataDir
	generation, err := windowsManagedRuntimeGenerationResolve(
		WindowsManagedRuntimeGenerationResolveOptions{
			Connector:               "codex",
			TargetSID:               currentSID.String(),
			DataDir:                 selected.DataDir,
			HookExecutable:          hookExecutable,
			MachinePolicyRegistered: true,
		},
	)
	if err != nil {
		return result, err
	}
	result.GatewayAddr = generation.GatewayAddr
	result.GatewayServiceName = generation.GatewayServiceName
	result.ScopedToken = generation.ScopedToken()
	result.GenerationID = generation.GenerationID
	result.FailMode = generation.FailMode
	result.Registered = true
	return result, nil
}

func windowsCodexMachineRequirementsPath() (string, error) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve trusted ProgramData: %w", err)
	}
	return filepath.Join(programData, "OpenAI", "Codex", "requirements.toml"), nil
}
