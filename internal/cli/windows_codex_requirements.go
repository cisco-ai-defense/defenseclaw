// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"github.com/spf13/cobra"
)

var (
	windowsCodexRequirementsLayoutResolver = resolveWindowsCodexRequirementsLayout
	windowsCodexRequirementsInspector      = connector.InspectWindowsCodexMachineRequirements
	windowsCodexRequirementsReconciler     = connector.ReconcileWindowsCodexMachineRequirements
	windowsCodexRequirementsVerifier       = connector.VerifyWindowsCodexMachineRequirements
	windowsCodexRequirementsRemover        = connector.RemoveWindowsCodexMachineRequirements
	windowsCodexRequirementsExecutable     = os.Executable
	windowsCodexRequirementsManifestTrust  = managed.ValidateTrustedFilePath
	windowsCodexRequirementsManifestLoader = enterprisehooks.LoadManifest
)

type windowsCodexDeploymentMetadata struct {
	SchemaVersion  int    `json:"schema_version"`
	DeploymentMode string `json:"deployment_mode"`
	Installed      *bool  `json:"installed,omitempty"`
	InstallRoot    string `json:"install_root"`
	StateRoot      string `json:"state_root"`
}

func newWindowsCodexRequirementsCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "codex-requirements",
		Short:  "Reconcile the protected Codex machine requirements",
		Hidden: true,
	}
	for _, action := range []string{"inspect", "reconcile", "verify", "remove"} {
		action := action
		var jsonOutput bool
		child := &cobra.Command{
			Use:          action,
			Short:        action + " protected Codex requirements",
			Hidden:       true,
			Args:         cobra.NoArgs,
			SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runWindowsCodexRequirementsAction(cmd, action, jsonOutput)
			},
		}
		child.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
		command.AddCommand(child)
	}
	return command
}

func runWindowsCodexRequirementsAction(cmd *cobra.Command, action string, jsonOutput bool) error {
	// Identity authorization intentionally precedes layout/config reads. A
	// standard user cannot use this hidden parser as a protected-file oracle.
	if err := enterpriseHooksNativePlatformPreflight(); err != nil {
		return writeWindowsCodexRequirementsFailure(cmd, action, jsonOutput, err)
	}
	opts, err := windowsCodexRequirementsLayoutResolver(action)
	if err != nil {
		return writeWindowsCodexRequirementsFailure(cmd, action, jsonOutput, err)
	}

	var report connector.WindowsCodexMachineRequirementsReport
	switch action {
	case "inspect":
		report, err = windowsCodexRequirementsInspector(opts)
	case "reconcile":
		report, err = windowsCodexRequirementsReconciler(opts)
	case "verify":
		report, err = windowsCodexRequirementsVerifier(opts)
	case "remove":
		report, err = windowsCodexRequirementsRemover(opts)
	default:
		err = fmt.Errorf("unsupported Codex requirements action %q", action)
	}
	if jsonOutput {
		if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(report); encodeErr != nil && err == nil {
			err = encodeErr
		}
	}
	if err != nil {
		if jsonOutput {
			return fmt.Errorf("Codex requirements %s failed", action)
		}
		return err
	}
	if !jsonOutput {
		fmt.Fprintf(
			cmd.OutOrStdout(),
			"Codex machine requirements %s: %s (changed=%t, security_complete=%t)\n",
			action,
			report.Disposition,
			report.Changed,
			report.SecurityComplete,
		)
	}
	return nil
}

func writeWindowsCodexRequirementsFailure(
	cmd *cobra.Command,
	action string,
	jsonOutput bool,
	cause error,
) error {
	if jsonOutput {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(connector.WindowsCodexMachineRequirementsReport{
			SchemaVersion:                       connector.WindowsCodexMachineRequirementsSchemaVersion,
			Action:                              action,
			OK:                                  false,
			AgentApplicationControlPrerequisite: "wdac_or_applocker_approved_agent_client_rules",
			Error:                               cause.Error(),
		})
		return fmt.Errorf("Codex requirements %s failed", action)
	}
	return cause
}

func resolveWindowsCodexRequirementsLayout(
	action string,
) (connector.WindowsCodexMachineRequirementsOptions, error) {
	var opts connector.WindowsCodexMachineRequirementsOptions
	if !managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return opts, fmt.Errorf("%s must be pinned to managed_enterprise", managed.DeploymentModeEnv)
	}
	executable, err := windowsCodexRequirementsExecutable()
	if err != nil {
		return opts, fmt.Errorf("resolve running gateway executable: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return opts, fmt.Errorf("resolve running gateway path: %w", err)
	}
	executable = filepath.Clean(executable)
	if !strings.EqualFold(filepath.Base(executable), "defenseclaw-gateway.exe") ||
		!strings.EqualFold(filepath.Base(filepath.Dir(executable)), "bin") {
		return opts, fmt.Errorf(
			"Codex requirements command must run from exact installed gateway <InstallRoot>\\bin\\defenseclaw-gateway.exe, got %s",
			executable,
		)
	}
	installRoot := filepath.Dir(filepath.Dir(executable))

	runtimeDir, err := exactWindowsCodexLayoutEnv("DEFENSECLAW_HOME")
	if err != nil {
		return opts, err
	}
	if !strings.EqualFold(filepath.Base(runtimeDir), "runtime") {
		return opts, fmt.Errorf("DEFENSECLAW_HOME must be the exact managed StateRoot\\runtime directory")
	}
	stateRoot := filepath.Dir(runtimeDir)
	configPath, err := exactWindowsCodexLayoutEnv("DEFENSECLAW_CONFIG")
	if err != nil {
		return opts, err
	}
	if !sameWindowsEnterprisePathCLI(configPath, filepath.Join(stateRoot, "etc", "config.yaml")) {
		return opts, errors.New("DEFENSECLAW_CONFIG does not match the derived managed StateRoot")
	}
	authorizationDir, err := exactWindowsCodexLayoutEnv(managed.HookGuardianAuthorizationDirEnv)
	if err != nil {
		return opts, err
	}
	if !sameWindowsEnterprisePathCLI(
		authorizationDir,
		filepath.Join(stateRoot, "hook-guardian-state"),
	) {
		return opts, fmt.Errorf(
			"%s does not match the derived managed StateRoot",
			managed.HookGuardianAuthorizationDirEnv,
		)
	}

	applicationControl, err := exactWindowsCodexAttestationEnv(
		connector.WindowsApprovedAgentClientsEnforcedEnv,
	)
	if err != nil {
		return opts, err
	}
	claudeEffectivePolicy, err := exactWindowsCodexAttestationEnv(
		connector.WindowsClaudeEffectivePolicyVerifiedEnv,
	)
	if err != nil {
		return opts, err
	}
	gatewayServiceName := os.Getenv(connector.WindowsGatewayServiceNameEnv)
	if err := connector.ValidateWindowsManagedGatewayServiceName(gatewayServiceName); err != nil {
		return opts, err
	}
	protectedConfig, err := config.LoadFromFile(configPath)
	if err != nil {
		return opts, fmt.Errorf("load protected Windows enterprise config: %w", err)
	}
	gatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(
		fmt.Sprintf("127.0.0.1:%d", protectedConfig.Gateway.APIPort),
	)
	if err != nil {
		return opts, err
	}

	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return opts, fmt.Errorf("resolve trusted ProgramData: %w", err)
	}
	requirementsPath := filepath.Join(programData, "OpenAI", "Codex", "requirements.toml")
	enterpriseTargetEnabled, codexTargetEnabled, claudeTargetEnabled, cursorTargetEnabled, err :=
		resolveWindowsCodexManifestApplicability(stateRoot)
	if err != nil {
		return opts, err
	}
	opts = connector.WindowsCodexMachineRequirementsOptions{
		RequirementsPath:                filepath.Clean(requirementsPath),
		ManagedDir:                      filepath.Join(installRoot, "bin"),
		HookBinary:                      filepath.Join(installRoot, "bin", "defenseclaw-hook.exe"),
		OwnershipPath:                   filepath.Join(stateRoot, "install", "codex-requirements-ownership.json"),
		ManagedStatePath:                filepath.Join(filepath.Dir(requirementsPath), ".defenseclaw-managed-hooks.state"),
		GatewayAddr:                     gatewayAddr,
		GatewayServiceName:              gatewayServiceName,
		AgentApplicationControlEnforced: applicationControl,
		EnterpriseTargetEnabled:         enterpriseTargetEnabled,
		ClaudeTargetEnabled:             claudeTargetEnabled,
		ClaudeEffectivePolicyVerified:   claudeEffectivePolicy,
		CodexTargetEnabled:              codexTargetEnabled,
		CursorTargetEnabled:             cursorTargetEnabled,
	}

	metadataPath := filepath.Join(stateRoot, "install", "deployment.json")
	metadata, exists, err := readWindowsCodexDeploymentMetadata(metadataPath)
	if err != nil {
		return connector.WindowsCodexMachineRequirementsOptions{}, err
	}
	if !exists {
		if action != "reconcile" && action != "inspect" && action != "lifecycle" {
			return connector.WindowsCodexMachineRequirementsOptions{}, fmt.Errorf(
				"Codex requirements %s requires protected deployment metadata",
				action,
			)
		}
		return opts, nil
	}
	if metadata.SchemaVersion != 1 ||
		!managed.IsManagedEnterprise(metadata.DeploymentMode) ||
		!sameWindowsEnterprisePathCLI(metadata.InstallRoot, installRoot) ||
		!sameWindowsEnterprisePathCLI(metadata.StateRoot, stateRoot) {
		return connector.WindowsCodexMachineRequirementsOptions{}, errors.New(
			"protected deployment metadata does not match the running gateway and strict service environment",
		)
	}
	if metadata.Installed != nil && !*metadata.Installed &&
		action != "remove" && action != "lifecycle" {
		return connector.WindowsCodexMachineRequirementsOptions{}, errors.New(
			"protected deployment metadata marks this installation inactive",
		)
	}
	return opts, nil
}

func resolveWindowsCodexManifestApplicability(
	stateRoot string,
) (enterpriseTargetEnabled, codexTargetEnabled, claudeTargetEnabled, cursorTargetEnabled bool, err error) {
	manifestPath := filepath.Join(stateRoot, "hook-guardian", "targets.yaml")
	if err := windowsCodexRequirementsManifestTrust(
		manifestPath,
		"Windows enterprise hook target manifest",
	); err != nil {
		return false, false, false, false, err
	}
	manifest, err := windowsCodexRequirementsManifestLoader(manifestPath)
	if err != nil {
		return false, false, false, false, err
	}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		enterpriseTargetEnabled = true
		switch strings.ToLower(strings.TrimSpace(target.Connector)) {
		case "codex":
			codexTargetEnabled = true
		case "claudecode":
			claudeTargetEnabled = true
		case "cursor":
			cursorTargetEnabled = true
		}
	}
	return enterpriseTargetEnabled, codexTargetEnabled, claudeTargetEnabled, cursorTargetEnabled, nil
}

func exactWindowsCodexAttestationEnv(name string) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value != "" && value != "1" {
		return false, fmt.Errorf("%s must be absent or exactly 1", name)
	}
	return value == "1", nil
}

func exactWindowsCodexLayoutEnv(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) {
		return "", fmt.Errorf("%s must be an exact absolute protected path", name)
	}
	clean := filepath.Clean(value)
	if clean != value {
		return "", fmt.Errorf("%s must already be canonical", name)
	}
	return clean, nil
}

func readWindowsCodexDeploymentMetadata(
	path string,
) (windowsCodexDeploymentMetadata, bool, error) {
	var metadata windowsCodexDeploymentMetadata
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return metadata, false, nil
	}
	if err != nil {
		return metadata, false, fmt.Errorf("inspect protected deployment metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 128<<10 {
		return metadata, false, errors.New("protected deployment metadata is not a bounded regular file")
	}
	if err := managed.ValidateTrustedFilePath(path, "Windows enterprise deployment metadata"); err != nil {
		return metadata, false, err
	}
	file, err := os.Open(path)
	if err != nil {
		return metadata, false, err
	}
	opened, statErr := file.Stat()
	body, readErr := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	closeErr := file.Close()
	if statErr != nil {
		return metadata, false, statErr
	}
	if readErr != nil {
		return metadata, false, readErr
	}
	if closeErr != nil {
		return metadata, false, closeErr
	}
	if len(body) > 128<<10 || !os.SameFile(info, opened) {
		return metadata, false, errors.New("protected deployment metadata changed while it was read")
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, current) {
		return metadata, false, errors.New("protected deployment metadata path changed while it was read")
	}
	// Windows PowerShell 5.1 historically wrote UTF-8 JSON with a BOM. Accept
	// that one exact legacy prefix while new lifecycle writes are BOM-less.
	body = trimWindowsJSONBOM(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&metadata); err != nil {
		return metadata, false, fmt.Errorf("parse protected deployment metadata: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return metadata, false, errors.New("protected deployment metadata contains trailing JSON")
	}
	return metadata, true, nil
}

func trimWindowsJSONBOM(body []byte) []byte {
	return bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
}

func sameWindowsEnterprisePathCLI(left, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil &&
		strings.EqualFold(filepath.Clean(leftAbs), filepath.Clean(rightAbs))
}
