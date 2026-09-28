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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var (
	enterprisePolicyConnector   string
	enterprisePolicyFormat      string
	enterprisePolicyJSON        bool
	enterprisePolicyUser        string
	enterprisePolicyProject     string
	enterprisePolicyLive        bool
	enterprisePolicyAgentBinary string
	enterprisePolicyAuditDB     string
	enterprisePolicyTimeout     time.Duration
)

var enterprisePolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Inspect, export and verify standalone machine agent policy",
	Long: `Inspect the machine agent policy the standalone managed_enterprise
profile publishes for each connector (Codex requirements.toml, Claude Code
managed settings, Cursor enterprise hooks, Copilot policy.d, OpenCode managed
config), export DefenseClaw's entries for an administrator's own policy tool,
and verify coverage statically or by running the real client as a user.

These commands never write machine policy; the install and reconcile
lifecycle does.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Refuse an unavailable live check before the elevation pin, so the
		// caller gets its reason instead of a refusal that points elsewhere.
		if enterprisePolicyLive && cmd.Name() == "verify" {
			if err := enterprisePolicyLiveAvailable(); err != nil {
				return err
			}
		}
		if err := pinStandaloneManagedEnv(); err != nil {
			return err
		}
		return rootPersistentPreRunNoAuditE(cmd, args)
	},
}

var enterprisePolicyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show each connector's route, lock and coverage",
	Args:  cobra.NoArgs,
	RunE:  runEnterprisePolicyShow,
}

var enterprisePolicyExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Print DefenseClaw's machine policy entries for one connector",
	Long: `Print DefenseClaw's entries for one connector in a format an
administrator can deploy through their own policy source:

  codex       toml (merged requirements.toml), plist (MDM requirements_toml_base64)
  claudecode  json (managed-settings.d drop-in), claude-hklm-json, reg, plist,
              intune-settings-catalog, version-floor (the separate
              requiredMinimumVersion drop-in, 00-defenseclaw-version-floor.json)
  cursor      json (enterprise hooks.json)
  copilot     json (policy.d drop-in)
  opencode    json (managed config)`,
	Args: cobra.NoArgs,
	RunE: runEnterprisePolicyExport,
}

var enterprisePolicyVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify machine policy coverage (exit 1 when incomplete)",
	Args:  cobra.NoArgs,
	RunE:  runEnterprisePolicyVerify,
}

func init() {
	for _, command := range []*cobra.Command{enterprisePolicyShowCmd, enterprisePolicyVerifyCmd} {
		command.Flags().StringVar(&enterprisePolicyConnector, "connector", "", "Limit to one connector")
		command.Flags().BoolVar(&enterprisePolicyJSON, "json", false, "Emit machine-readable JSON")
		command.Flags().StringVar(&enterprisePolicyUser, "user", "", "Also check this local user's own agent config")
	}
	enterprisePolicyShowCmd.Flags().StringVar(&enterprisePolicyProject, "project", "", "With --user, also scan this project directory for foreign hooks")
	enterprisePolicyExportCmd.Flags().StringVar(&enterprisePolicyConnector, "connector", "", "Connector to export (required)")
	enterprisePolicyExportCmd.Flags().StringVar(&enterprisePolicyFormat, "format", "", "Output format (see --help); default is the connector's native file")
	_ = enterprisePolicyExportCmd.MarkFlagRequired("connector")
	enterprisePolicyVerifyCmd.Flags().BoolVar(&enterprisePolicyLive, "live", false, "Run the real client as --user and prove it loads DefenseClaw's hooks (codex, claudecode)")
	enterprisePolicyVerifyCmd.Flags().StringVar(&enterprisePolicyAgentBinary, "agent-binary", "", "Absolute path of the client binary for --live")
	enterprisePolicyVerifyCmd.Flags().StringVar(&enterprisePolicyAuditDB, "audit-db", "", "Gateway audit database whose event history is searched for the Claude Code canary tool call (default: the configured audit_db)")
	enterprisePolicyVerifyCmd.Flags().DurationVar(&enterprisePolicyTimeout, "timeout", 90*time.Second, "Live check timeout")
	enterprisePolicyCmd.AddCommand(enterprisePolicyShowCmd, enterprisePolicyExportCmd, enterprisePolicyVerifyCmd)
	enterpriseCmd.AddCommand(enterprisePolicyCmd)
}

// enterprisePolicyContext is everything the policy commands share.
type enterprisePolicyContext struct {
	layout     managed.StandaloneLayout
	opts       enterprisepolicy.Options
	connectors []string
}

// standaloneEnterprisePolicyOptions is replaceable in tests.
var standaloneEnterprisePolicyOptions = func() (enterprisePolicyContext, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return enterprisePolicyContext{}, errors.New("enterprise policy commands require deployment_mode: managed_enterprise with enterprise.profile: standalone (Secure Client manages its own machine policy)")
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return enterprisePolicyContext{}, err
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return enterprisePolicyContext{}, err
	}
	return enterprisePolicyContext{layout: layout, opts: opts, connectors: enterprisepolicy.StandaloneConnectors(cfg)}, nil
}

func (c enterprisePolicyContext) selected() ([]string, error) {
	name := strings.ToLower(strings.TrimSpace(enterprisePolicyConnector))
	if name == "" {
		return c.connectors, nil
	}
	if enterprisepolicy.RouteFor(name, c.opts.GOOS) == enterprisepolicy.RouteUnsupported {
		if _, ok := enterprisepolicy.TargetFor(name); !ok {
			return nil, fmt.Errorf("unknown or unsupported connector %q", name)
		}
	}
	return []string{name}, nil
}

// enterprisePolicyUserReport is the per-user part of show/verify.
type enterprisePolicyUserReport struct {
	User string `json:"user"`
	Home string `json:"home"`
	// Enrollment says why the enumerator never enrolls this account
	// (Linux and macOS), or is empty.
	Enrollment string                                    `json:"enrollment,omitempty"`
	Decisions  map[string]enterprisepolicy.GuardDecision `json:"foreign_hooks"`
	Live       []enterprisepolicy.LiveResult             `json:"live,omitempty"`
	Error      string                                    `json:"error,omitempty"`
}

type enterprisePolicyReport struct {
	Profile    string                                            `json:"profile"`
	HookBinary string                                            `json:"hook_binary"`
	Complete   bool                                              `json:"complete"`
	Result     enterprisepolicy.Result                           `json:"result"`
	Guard      map[string]enterprisepolicy.PublicConnectorPolicy `json:"guard"`
	User       *enterprisePolicyUserReport                       `json:"user,omitempty"`
	// goos is the host the report describes; it only changes wording.
	goos string
}

func buildEnterprisePolicyReport(ctx enterprisePolicyContext, connectors []string, project string) (enterprisePolicyReport, error) {
	result, err := enterprisepolicy.VerifyAll(ctx.opts, connectors)
	summary := enterprisepolicy.BuildPublicPolicy(ctx.opts, connectors)
	report := enterprisePolicyReport{
		Profile:    managed.ProfileStandalone,
		HookBinary: ctx.opts.HookBinary,
		Complete:   err == nil && result.Complete(),
		Result:     result,
		Guard:      summary.Connectors,
		goos:       ctx.opts.GOOS,
	}
	if strings.TrimSpace(enterprisePolicyUser) == "" {
		return report, err
	}
	userReport := &enterprisePolicyUserReport{User: enterprisePolicyUser, Decisions: map[string]enterprisepolicy.GuardDecision{}}
	report.User = userReport
	target, targetErr := enterprisePolicyResolveTarget(enterprisePolicyUser)
	if targetErr != nil {
		userReport.Error = targetErr.Error()
		report.Complete = false
		return report, errors.Join(err, targetErr)
	}
	userReport.Home = target.UserHome
	if ctx.opts.GOOS != "windows" && cfg != nil {
		// Match the name the account database returns, as the enumerator
		// does: macOS resolves a differently cased name to the same account.
		name := strings.TrimSpace(target.Username)
		if name == "" {
			name = enterprisePolicyUser
		}
		userReport.Enrollment = unixEnrollmentExclusion(cfg.Enterprise.Enrollment, name, target.UID)
	}
	scanErr := runAsEnterprisePolicyTarget(target, func() error {
		for _, name := range connectors {
			policy, ok := summary.Connectors[name]
			if !ok || !policy.Guard {
				continue
			}
			decision := enterprisepolicy.EvaluateForeignHooks(enterprisepolicy.GuardRequest{
				Connector:     name,
				GOOS:          ctx.opts.GOOS,
				Home:          target.UserHome,
				AccountHome:   target.UserHome,
				WorkingDir:    project,
				HookBinary:    ctx.opts.HookBinary,
				Policy:        policy,
				OwnedCommands: perUserOwnedHookCommands(name, target.UserHome, ""),
			})
			userReport.Decisions[name] = decision
			if decision.Deny {
				report.Complete = false
			}
		}
		return nil
	})
	if scanErr != nil {
		userReport.Error = scanErr.Error()
		report.Complete = false
	}
	return report, errors.Join(err, scanErr)
}

// enterprisePolicyResolveTarget resolves --user; replaceable in tests.
var enterprisePolicyResolveTarget = enterprisePolicyTarget

// unixEnrollmentExclusion names the Linux and macOS enrollment rule that
// keeps an account out of the guardian manifest regardless of its agents:
// exclude_users, exempt_users (both match the name or the decimal uid, as
// the enumerator does) and uid 0. It returns "" for any other account.
func unixEnrollmentExclusion(enrollment config.EnterpriseEnrollmentConfig, name string, uid int) string {
	listed := func(values []string) bool {
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" && (value == name || value == strconv.Itoa(uid)) {
				return true
			}
		}
		return false
	}
	switch {
	case listed(enrollment.ExcludeUsers):
		return "excluded by enterprise.enrollment.exclude_users: never enrolled, so DefenseClaw installs no per-user hooks for this account"
	case listed(enrollment.ExemptUsers):
		return "exempt by enterprise.enrollment.exempt_users: not enrolled; its agent calls are allowed, inspected and logged"
	case uid == 0:
		root := strings.TrimSpace(enrollment.Root)
		if root == "" {
			root = config.EnterpriseRootInspect
		}
		return "root is never enrolled; enterprise.enrollment.root (" + root + ") decides how its agent calls are treated"
	}
	return ""
}

func runEnterprisePolicyShow(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true
	ctx, err := standaloneEnterprisePolicyOptions()
	if err != nil {
		return err
	}
	connectors, err := ctx.selected()
	if err != nil {
		return err
	}
	project := strings.TrimSpace(enterprisePolicyProject)
	if project != "" && !filepath.IsAbs(project) {
		return errors.New("--project must be an absolute path")
	}
	report, reportErr := buildEnterprisePolicyReport(ctx, connectors, project)
	if err := writeEnterprisePolicyReport(cmd.OutOrStdout(), report); err != nil {
		return err
	}
	return reportErr
}

func runEnterprisePolicyVerify(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true
	ctx, err := standaloneEnterprisePolicyOptions()
	if err != nil {
		return err
	}
	connectors, err := ctx.selected()
	if err != nil {
		return err
	}
	if enterprisePolicyLive && (strings.TrimSpace(enterprisePolicyUser) == "" || len(connectors) != 1 || strings.TrimSpace(enterprisePolicyAgentBinary) == "") {
		return errors.New("--live needs --user, --connector (codex or claudecode) and --agent-binary")
	}
	report, reportErr := buildEnterprisePolicyReport(ctx, connectors, "")
	if enterprisePolicyLive && report.User != nil && report.User.Error == "" {
		target, _ := enterprisePolicyTarget(enterprisePolicyUser)
		live, liveErr := enterprisepolicy.VerifyLive(cmd.Context(), ctx.opts, enterprisepolicy.LiveOptions{
			Connector:   connectors[0],
			AgentBinary: enterprisePolicyAgentBinary,
			Home:        target.UserHome,
			UID:         target.UID,
			GID:         target.GID,
			Timeout:     enterprisePolicyTimeout,
			AuditDB:     enterprisePolicyAuditDBPath(),
			Credential:  enterprisePolicyLiveCredential(target),
		})
		if liveErr != nil {
			live.Problems = append(live.Problems, liveErr.Error())
		}
		report.User.Live = append(report.User.Live, live)
		if !live.Verified {
			report.Complete = false
		}
	}
	if err := writeEnterprisePolicyReport(cmd.OutOrStdout(), report); err != nil {
		return err
	}
	if reportErr != nil {
		return reportErr
	}
	if !report.Complete {
		return errors.New("enterprise machine policy is incomplete")
	}
	return nil
}

func runEnterprisePolicyExport(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true
	ctx, err := standaloneEnterprisePolicyOptions()
	if err != nil {
		return err
	}
	data, err := enterprisepolicy.Export(ctx.opts, strings.ToLower(strings.TrimSpace(enterprisePolicyConnector)), strings.ToLower(strings.TrimSpace(enterprisePolicyFormat)))
	if err != nil {
		return err
	}
	_, err = cmd.OutOrStdout().Write(data)
	return err
}

// enterprisePolicyAuditDBPath is the audit database whose v8 event history
// holds the record the Claude Code canary tool call leaves.
func enterprisePolicyAuditDBPath() string {
	if value := strings.TrimSpace(enterprisePolicyAuditDB); value != "" {
		return value
	}
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.AuditDB)
}

func writeEnterprisePolicyReport(out io.Writer, report enterprisePolicyReport) error {
	if enterprisePolicyJSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	fmt.Fprintf(out, "Standalone machine agent policy (hook binary %s)\n\n", report.HookBinary)
	for _, state := range report.Result.States {
		if state.Ownership == config.MachinePolicyOwnershipOff && report.goos != "windows" &&
			enterprisepolicy.RouteFor(state.Connector, report.goos) == enterprisepolicy.RouteMachinePolicy {
			// Not "unsupported": the administrator turned DefenseClaw's
			// management of this agent off. OpenCode keeps its per-user
			// plugin and its usual row.
			fmt.Fprintf(out, "%-12s ownership off: machine policy not managed\n", state.Connector)
			fmt.Fprintf(out, "    note:      DefenseClaw neither writes nor checks this agent's machine policy and installs no per-user hooks for it, so its sessions run without DefenseClaw's hooks; set ownership to merge or verify_only to protect it\n")
			continue
		}
		status := "not covered"
		switch {
		case state.Route != enterprisepolicy.RouteMachinePolicy:
			status = "n/a"
		case state.Covered:
			status = "covered"
		}
		lock := state.EffectiveLock
		if lock == "" {
			lock = "-"
		}
		fmt.Fprintf(out, "%-12s %-15s %-12s lock=%-8s foreign_hooks=%-7s owned=%d foreign=%d\n",
			state.Connector, state.Route, status, lock, dashIfEmpty(state.ForeignHooks), state.OwnedEntries, state.ForeignEntries)
		for _, path := range state.Paths {
			fmt.Fprintf(out, "    file:      %s\n", path)
		}
		if state.VersionFloor != nil {
			fmt.Fprintf(out, "    floor:     %s\n", state.VersionFloor.Summary())
		}
		for _, conflict := range state.Conflicts {
			fmt.Fprintf(out, "    conflict:  %s\n", conflict)
		}
		for _, pending := range state.Pending {
			fmt.Fprintf(out, "    pending:   %s\n", pending)
		}
		for _, detail := range state.Details {
			fmt.Fprintf(out, "    note:      %s\n", detail)
		}
		if guard, ok := report.Guard[state.Connector]; ok && guard.Guard {
			fmt.Fprintf(out, "    guard:     foreign hooks %s (%d allowlisted)\n", guard.ForeignHooks, len(guard.AllowedHooks))
		}
	}
	if report.User != nil {
		fmt.Fprintf(out, "\nUser %s (%s)\n", report.User.User, dashIfEmpty(report.User.Home))
		if report.User.Enrollment != "" {
			fmt.Fprintf(out, "    enrollment: %s\n", report.User.Enrollment)
		}
		if report.User.Error != "" {
			fmt.Fprintf(out, "    error: %s\n", report.User.Error)
		}
		// Name order, so two accounts' reports compare line by line.
		names := make([]string, 0, len(report.User.Decisions))
		for name := range report.User.Decisions {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			decision := report.User.Decisions[name]
			if len(decision.Findings) == 0 {
				fmt.Fprintf(out, "    %-12s no foreign hooks\n", name)
				continue
			}
			for _, finding := range decision.Findings {
				state := "blocked"
				if finding.Allowed {
					state = "allowlisted"
				} else if !decision.Deny {
					state = "reported"
				}
				fmt.Fprintf(out, "    %-12s %-11s %s %s %s sha256:%s\n", name, state, finding.Scope, finding.Path, dashIfEmpty(finding.Event), finding.Digest)
			}
		}
		for _, live := range report.User.Live {
			verdict := "FAILED"
			if live.Verified {
				verdict = "verified"
			}
			fmt.Fprintf(out, "    live %-7s %s (hook contact: %s)\n", live.Connector, verdict, live.HookContact)
			for _, line := range live.Evidence {
				fmt.Fprintf(out, "        + %s\n", line)
			}
			for _, line := range live.Problems {
				fmt.Fprintf(out, "        - %s\n", line)
			}
		}
	}
	if report.Complete {
		fmt.Fprintln(out, "\nResult: complete")
	} else {
		fmt.Fprintln(out, "\nResult: INCOMPLETE")
	}
	return nil
}

func dashIfEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
