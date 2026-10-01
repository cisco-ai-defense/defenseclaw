// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Registered from this file so the lifecycle command table stays untouched.
func init() {
	enterpriseWindowsCmd.AddCommand(newWindowsClaudePolicyExportCommand())
}

var windowsClaudePolicyExportExecutable = os.Executable

type windowsClaudePolicyExportOptions struct {
	hookExecutable string
	agentVersion   string
	compact        bool
}

func newWindowsClaudePolicyExportCommand() *cobra.Command {
	opts := &windowsClaudePolicyExportOptions{}
	cmd := &cobra.Command{
		Use:   "export-claude-policy",
		Short: "Print the DefenseClaw Claude Code managed hook matrix as policy JSON",
		Long: `Print the exact DefenseClaw Claude Code hook matrix as managed-policy JSON.

Claude Code applies the highest-ranked managed source. An MDM or GPO policy in
HKLM\SOFTWARE\Policies\ClaudeCode\Settings outranks the DefenseClaw
managed-settings.d drop-in, so enrollment refuses it unless that policy either
sets "managedSourcesBehavior": "merge" (Claude Code ` + connector.ClaudeCodeManagedSourcesMergeMinimumVersion + ` or newer) or
already contains this hook matrix exactly. Pass --agent-version with the
agent_version recorded for the target, which the enrollment refusal names:
the hook contract depends on it, and without it the oldest supported contract
is printed. Add the printed "hooks" object to that
policy, and the printed "allowManagedHooksOnly": true unless the DefenseClaw
config sets claude_code.allow_unmanaged_hooks: true; Claude then loads only
that policy, so enrollment refuses one that carries the hooks without the
lock. The output names the installed hook executable and contains no
credentials. It is read-only and needs no elevation.`,
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWindowsClaudePolicyExport(cmd, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.hookExecutable, "hook-executable", "",
		"absolute path of defenseclaw-hook.exe (default: the hook beside this installed gateway)")
	flags.StringVar(&opts.agentVersion, "agent-version", "",
		"agent_version recorded for the target, which selects the hook contract to render (default: the oldest supported contract; the enrollment refusal names the version to pass)")
	flags.BoolVar(&opts.compact, "compact", false,
		"print single-line JSON, suitable for a REG_SZ value")
	return cmd
}

func runWindowsClaudePolicyExport(cmd *cobra.Command, opts *windowsClaudePolicyExportOptions) error {
	hook, err := resolveWindowsClaudePolicyExportHook(opts.hookExecutable)
	if err != nil {
		return err
	}
	agentVersion := strings.TrimSpace(opts.agentVersion)
	resolution := connector.ResolveHookContract("claudecode", agentVersion)
	if resolution.Contract.ContractID == "" {
		return fmt.Errorf("Claude Code version %q has no DefenseClaw hook contract: %s", agentVersion, resolution.Reason)
	}
	body, err := connector.ClaudeCodeManagedHookPolicyDocument(connector.SetupOpts{
		ManagedEnterprise: true,
		HookFailMode:      "closed",
		HookExecutable:    hook,
		AgentVersion:      agentVersion,
		HookContractID:    resolution.Contract.ContractID,
	})
	if err != nil {
		return err
	}
	if opts.compact {
		var compacted bytes.Buffer
		if err := json.Compact(&compacted, body); err != nil {
			return fmt.Errorf("compact Claude Code managed hook policy: %w", err)
		}
		body = append(compacted.Bytes(), '\n')
	}
	_, err = cmd.OutOrStdout().Write(body)
	return err
}

// resolveWindowsClaudePolicyExportHook returns the hook the guardian pins in
// the managed policy. The matrix is compared exactly, so an exported command
// path must be the installed one.
func resolveWindowsClaudePolicyExportHook(explicit string) (string, error) {
	hook := strings.TrimSpace(explicit)
	if hook == "" {
		executable, err := windowsClaudePolicyExportExecutable()
		if err != nil {
			return "", fmt.Errorf("resolve running gateway executable: %w", err)
		}
		executable, err = filepath.Abs(executable)
		if err != nil {
			return "", fmt.Errorf("resolve running gateway path: %w", err)
		}
		executable = filepath.Clean(executable)
		if !strings.EqualFold(filepath.Base(executable), "defenseclaw-gateway.exe") ||
			!strings.EqualFold(filepath.Base(filepath.Dir(executable)), "bin") {
			return "", errors.New(
				"run export-claude-policy from the installed <InstallRoot>\\bin\\defenseclaw-gateway.exe, or pass --hook-executable",
			)
		}
		hook = filepath.Join(filepath.Dir(executable), "defenseclaw-hook.exe")
	}
	if !filepath.IsAbs(hook) || filepath.Clean(hook) != hook {
		return "", fmt.Errorf("--hook-executable must be a clean absolute path: %s", hook)
	}
	if !strings.EqualFold(filepath.Base(hook), "defenseclaw-hook.exe") {
		return "", fmt.Errorf("--hook-executable must name defenseclaw-hook.exe: %s", hook)
	}
	return hook, nil
}
