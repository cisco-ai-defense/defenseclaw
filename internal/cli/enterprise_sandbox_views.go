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
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The administrator's sandbox views (plan section 7.2): which sandboxes the
// users of this computer registered and the policy each one runs under, and
// the sandbox part of `profile-explain`. They read the gateway's
// registration store, which only the service account and root can read, so
// they run as root and show everything; a user sees only their own policy
// through `defenseclaw sandbox policy explain`.

// sandboxRegistrationStore opens the gateway's registration store under
// dataDir (<DataDir>/sandbox/registrations, the file store the managed
// gateway writes) for an administrator view; the views only read it. Tests
// replace it.
var sandboxRegistrationStore = func(dataDir string) (sandboxreg.Store, error) {
	return sandboxreg.NewFileStore(sandboxreg.RegistrationsDir(dataDir)), nil
}

// sandboxFloorFor is Config.SandboxFloor: the sandbox floor F of a profile
// ("" = openshell.admin alone) and its digest. Tests replace it; while it
// is nil the views list the organization's keys and the profile's keys
// apart and leave the resolved floor out.
var sandboxFloorFor = (*config.Config).SandboxFloor

// sandboxViewsRefusal refuses the sandbox administrator views for anyone but
// root: the registration store is the service's and the views show every
// account's sandboxes.
func sandboxViewsRefusal(cmd *cobra.Command) error {
	if err := refuseEnterpriseIdentityViewForStandardUser(cmd); err != nil {
		return err
	}
	if uid := managedHostCallerUID(); uid != 0 && runtime.GOOS != "windows" {
		command := strings.TrimSpace(strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()))
		return fmt.Errorf("`%s` shows every account's sandboxes, so an administrator runs it: `sudo %s %s`; "+
			"to see your own policy run `defenseclaw sandbox policy explain`", command, managedHostGatewayCommand(), command)
	}
	return nil
}

// newEnterpriseSandboxCommand is `enterprise <platform> sandbox`.
func newEnterpriseSandboxCommand(platform string) *cobra.Command {
	group := &cobra.Command{
		Use:   "sandbox",
		Short: "List the sandboxes users registered and explain the policy of one (read-only)",
		Long: `List the sandboxes the users of this computer registered with the managed gateway,
and explain the policy one of them runs under. Both only read; run them as root
on Linux and macOS, or from an elevated Administrator prompt on Windows.
A user sees only their own policy: defenseclaw sandbox policy explain.`,
		SilenceUsage: true,
		// A Secure Client computer has no sandbox registrations.
		Annotations: map[string]string{enterpriseIdentityViewAnnotation: "sandbox"},
		RunE:        func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	group.AddCommand(newEnterpriseSandboxListCommand(platform), newEnterpriseSandboxExplainCommand(platform),
		newEnterpriseSandboxPackDigestCommand(platform))
	return group
}

// sandboxPackDigest is `sandbox pack-digest`: what the administrator pins.
type sandboxPackDigest struct {
	Name    string `json:"name"`
	Source  string `json:"source"`
	Profile string `json:"profile"`
	Digest  string `json:"digest"`
	// Extends names the packs it extends, nearest first; the digest covers
	// the whole chain.
	Extends []string `json:"extends,omitempty"`
	// Trusted is false when the gateway of a managed deployment would refuse
	// the file where it is (not administrator-owned, or writable by others);
	// Note says why.
	Trusted bool   `json:"trusted"`
	Note    string `json:"note,omitempty"`
}

// newEnterpriseSandboxPackDigestCommand is `enterprise <os> sandbox
// pack-digest`: the digest of a pack for openshell.admin.required_pack_digest
// or a profile's required_pack_digest. `defenseclaw sandbox pack show` asks
// the caller's own sandbox daemon, which root does not have on a managed
// computer, so the administrator had no way to read it (GAP-0224). This only
// reads the file: no gateway, no daemon, no installed deployment needed.
func newEnterpriseSandboxPackDigestCommand(platform string) *cobra.Command {
	var packDir string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "pack-digest <pack>",
		Short: "Print a pack's digest for required_pack_digest (reads the file only)",
		Long: `Print the sha256 digest of a sandbox policy pack, the value
openshell.admin.required_pack_digest and a profile's sandbox.required_pack_digest
pin. <pack> is a pack.yaml, a pack directory, a built-in pack (open, balanced,
strict) or a pack name in the packs directory (--pack-dir, or the installed
deployment's openshell.pack_dir when root can read its config).

It reads the file and the packs it extends, and nothing else. It also says
whether a managed deployment's gateway would accept the file where it is: a
required pack must be an administrator-owned file other users cannot modify.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if goos := enterprisePlatformGOOS(platform); runtime.GOOS != goos {
				return invalidLifecycleArguments(fmt.Errorf("`%s` reads %s hosts; this host is %s",
					strings.TrimSpace(strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name())), goos, runtime.GOOS))
			}
			if strings.TrimSpace(packDir) == "" && managedHostCallerUID() == 0 {
				packDir = installedSandboxPackDir(cmd)
			}
			out, err := sandboxPackDigestOf(args[0], packDir)
			if err != nil {
				return withExitCode(err, enterprisestatus.UnixExitFailure)
			}
			if asJSON {
				return writeSandboxViewJSON(cmd.OutOrStdout(), out)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "pack %s (profile %s) %s\n", sandboxapi.DisplayText(out.Name), sandboxapi.DisplayText(out.Profile), sandboxapi.DisplayText(out.Source))
			if len(out.Extends) > 0 {
				fmt.Fprintf(w, "  extends     %s\n", sandboxapi.DisplayText(strings.Join(out.Extends, ", ")))
			}
			fmt.Fprintf(w, "  digest      %s\n", out.Digest)
			fmt.Fprintf(w, "  pin it with required_pack_digest: %q\n", out.Digest)
			if out.Note != "" {
				fmt.Fprintf(w, "  note        %s\n", sandboxapi.DisplayText(out.Note))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&packDir, "pack-dir", "", "the packs directory a pack name, or a pack it extends, is looked up in")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// installedSandboxPackDir is the installed deployment's openshell.pack_dir,
// or "" when its config does not load (none installed yet).
func installedSandboxPackDir(cmd *cobra.Command) string {
	runtimeCommand = cmd
	if enterpriseDiscoveryPinManagedEnv() != nil || enterpriseDiscoveryLoadConfig(cmd) != nil || cfg == nil {
		return ""
	}
	return cfg.OpenShell.PackDir
}

// sandboxPackDigestOf loads ref with the administrator-owned file rule a
// managed gateway applies to a required pack, and without it when the file
// fails only that rule, so the digest is still printed with the reason.
func sandboxPackDigestOf(ref, packDir string) (sandboxPackDigest, error) {
	home, _ := os.UserHomeDir()
	subject := packs.Subject{UID: os.Geteuid(), Home: home}
	trusted := true
	note := ""
	pack, err := packs.LoadRequired(subject, ref, packDir, true)
	var packErr *packs.Error
	if errors.As(err, &packErr) && packErr.Code == "untrusted" {
		trusted, note = false, "a managed deployment's gateway refuses this file where it is: "+packErr.Error()
		pack, err = packs.LoadRequired(subject, ref, packDir, false)
	}
	if err != nil {
		return sandboxPackDigest{}, fmt.Errorf("read the pack %s: %w", ref, err)
	}
	out := sandboxPackDigest{Name: pack.Name, Source: pack.Source, Profile: pack.Profile(), Digest: pack.Digest, Trusted: trusted, Note: note}
	if pack.Builtin {
		out.Source = "built-in"
		out.Note = "a built-in pack's digest can change with a DefenseClaw upgrade; read it again after each one"
	}
	for _, link := range pack.Chain {
		out.Extends = append(out.Extends, link.Name)
	}
	return out, nil
}

// sandboxViewStore checks the caller and the deployment and opens the store;
// asJSON gives a refused caller the JSON refusal.
func sandboxViewStore(cmd *cobra.Command, platform string, asJSON bool) (sandboxreg.Store, error) {
	view := strings.TrimSpace(strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()))
	if goos := enterprisePlatformGOOS(platform); runtime.GOOS != goos {
		return nil, invalidLifecycleArguments(fmt.Errorf("`%s` reads %s hosts; this host is %s", view, goos, runtime.GOOS))
	}
	if err := sandboxViewsRefusal(cmd); err != nil {
		return nil, managedAdminViewRefusal(cmd, err, asJSON)
	}
	runtimeCommand = cmd
	// Read the managed deployment's own config, as profile-explain does
	// through enterpriseGatewayGet. Nothing else loads it for the
	// `enterprise <os>` groups, so cfg was unset and a verified standalone
	// deployment was refused (GAP-0182, GAP-0242).
	if err := enterpriseDiscoveryPinManagedEnv(); err != nil {
		return nil, withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if err := enterpriseDiscoveryLoadConfig(cmd); err != nil {
		return nil, withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil, withExitCode(fmt.Errorf("`%s` needs a standalone managed deployment (deployment_mode: managed_enterprise, enterprise.profile: standalone)", view),
			enterprisestatus.UnixExitFailure)
	}
	store, err := sandboxRegistrationStore(cfg.DataDir)
	if err != nil {
		return nil, withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	return store, nil
}

func newEnterpriseSandboxListCommand(platform string) *cobra.Command {
	var user, state string
	var asJSON bool
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List the registered sandboxes of every account (or one with --user)",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch state {
			case "", sandboxreg.StatePending, sandboxreg.StateExpired, sandboxreg.StateLive, sandboxreg.StateStopped, sandboxreg.StateRevoked:
			default:
				return invalidLifecycleArguments(fmt.Errorf("--state takes %s, %s, %s, %s or %s", sandboxreg.StatePending, sandboxreg.StateExpired,
					sandboxreg.StateLive, sandboxreg.StateStopped, sandboxreg.StateRevoked))
			}
			store, err := sandboxViewStore(cmd, platform, asJSON)
			if err != nil {
				return err
			}
			all, err := store.ListAll()
			if err != nil {
				return withExitCode(fmt.Errorf("read the sandbox registrations: %w", err), enterprisestatus.UnixExitFailure)
			}
			filterUser := strings.TrimSpace(user)
			if strings.ContainsAny(filterUser, `@\`) {
				// A qualified name must identify an account in that domain.
				// Resolve it as policy verify does, then select its UID: a
				// registration's bare name cannot establish its domain.
				target, err := enterprisePolicyResolveTarget(filterUser)
				if err != nil {
					return invalidLifecycleArguments(fmt.Errorf("resolve --user %q: %w", filterUser, err))
				}
				filterUser = strconv.Itoa(target.UID)
			}
			list := filterRegistrations(all, filterUser, state, time.Now())
			if asJSON {
				return writeSandboxViewJSON(cmd.OutOrStdout(), map[string]any{"total": len(list), "registrations": list})
			}
			printRegistrations(cmd.OutOrStdout(), list)
			return nil
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "only this account (name, user@domain, DOMAIN\\user or uid)")
	cmd.Flags().StringVar(&state, "state", "", "only registrations in this state (pending, expired, live, stopped or revoked)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func newEnterpriseSandboxExplainCommand(platform string) *cobra.Command {
	var id string
	var asJSON bool
	cmd := &cobra.Command{
		Use:          "explain",
		Short:        "Explain the policy one registered sandbox runs under, with where each value comes from",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(id) == "" {
				return invalidLifecycleArguments(errors.New("--registration is required; `sandbox list` shows the ids"))
			}
			store, err := sandboxViewStore(cmd, platform, asJSON)
			if err != nil {
				return err
			}
			all, err := store.ListAll()
			if err != nil {
				return withExitCode(fmt.Errorf("read the sandbox registrations: %w", err), enterprisestatus.UnixExitFailure)
			}
			var reg *sandboxreg.Registration
			for i := range all {
				if all[i].ID == strings.TrimSpace(id) {
					all[i].State = sandboxreg.EffectiveState(all[i], time.Now())
					reg = &all[i]
				}
			}
			if reg == nil {
				return withExitCode(fmt.Errorf("no registration %q; `sandbox list` shows the ids", id), enterprisestatus.UnixExitFailure)
			}
			view := explainRegistration(cfg, *reg)
			if asJSON {
				return writeSandboxViewJSON(cmd.OutOrStdout(), view)
			}
			printRegistrationExplain(cmd.OutOrStdout(), view, time.Now())
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "registration", "", "the registration id (reg-...), from `sandbox list`")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// filterRegistrations keeps the registrations of an account (name or uid) and
// a state, oldest first, each in its state at now (sandboxreg.EffectiveState):
// a pending one past sandboxreg.PendingTTL is expired, and a live one whose daemon
// stopped reporting its sandbox running is stopped (GAP-0479, GAP-0488).
func filterRegistrations(all []sandboxreg.Registration, user, state string, now time.Time) []sandboxreg.Registration {
	user = strings.TrimSpace(user)
	list := []sandboxreg.Registration{}
	for _, r := range all {
		name, _ := useridentity.SplitQualifiedName(r.UserName)
		if user != "" && strconv.Itoa(r.UID) != user && !strings.EqualFold(name, user) {
			continue
		}
		r.State = sandboxreg.EffectiveState(r, now)
		if state != "" && r.State != state {
			continue
		}
		list = append(list, r)
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	return list
}

func printRegistrations(w io.Writer, list []sandboxreg.Registration) {
	if len(list) == 0 {
		fmt.Fprintln(w, "no sandbox registrations")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tUSER\tUID\tSTATE\tPROFILE\tMATCH\tAGENT\tSANDBOX\tDRIVER\tCREATED")
	for _, r := range list {
		profile := r.Profile
		if profile == "" {
			profile = "(floor)"
		}
		match := r.ProfileMatch
		if r.Provisional {
			match += " (provisional)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", sandboxapi.DisplayText(r.ID), sandboxapi.DisplayText(r.UserName), r.UID,
			sandboxapi.DisplayText(r.State), sandboxapi.DisplayText(profile), sandboxapi.DisplayText(match), sandboxapi.DisplayText(r.Harness),
			sandboxapi.DisplayText(firstNonEmptyString(r.SandboxName, "-")), sandboxapi.DisplayText(firstNonEmptyString(r.Driver, "-")),
			r.CreatedAt.UTC().Format(time.RFC3339))
	}
	_ = tw.Flush()
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func writeSandboxViewJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// registrationExplain is `sandbox explain --registration`: the registration
// and the policy it runs under, with sources.
type registrationExplain struct {
	Registration sandboxreg.Registration `json:"registration"`
	Policy       sandboxPolicyView       `json:"policy"`
	// Managed is the user's own view (what `sandbox policy explain` shows
	// them), built from the floor.
	Managed *sandboxapi.ManagedExplain `json:"managed,omitempty"`
}

// sandboxPolicyView is the sandbox policy of a profile: the organization's
// keys (openshell.admin, everyone's floor), the profile's overlay, the
// resolved floor F and its digest when the config can resolve it, and the
// source of each key.
type sandboxPolicyView struct {
	Profile      string            `json:"profile"`
	Organization map[string]any    `json:"organization,omitempty"`
	Overlay      map[string]any    `json:"overlay,omitempty"`
	Floor        map[string]any    `json:"floor,omitempty"`
	Digest       string            `json:"digest,omitempty"`
	Sources      map[string]string `json:"sources,omitempty"`
	FloorError   string            `json:"floor_error,omitempty"`
	floor        config.OpenShellAdminConfig
	hasFloor     bool
	base         config.OpenShellAdminConfig
	overlay      *config.OpenShellAdminConfig
}

// adminKeyMap is the set keys of an admin config as the YAML shows them.
func adminKeyMap(v config.OpenShellAdminConfig) map[string]any {
	raw, err := yaml.Marshal(v)
	if err != nil {
		return nil
	}
	out := map[string]any{}
	if yaml.Unmarshal(raw, &out) != nil || len(out) == 0 {
		return nil
	}
	return out
}

// sandboxPolicyOf builds the sandbox policy view of profile under c.
func sandboxPolicyOf(c *config.Config, profile string) sandboxPolicyView {
	view := sandboxPolicyView{Profile: profile}
	if c == nil {
		return view
	}
	base := c.OpenShell.Admin
	view.Organization = adminKeyMap(base)
	var overlay *config.OpenShellAdminConfig
	if p, ok := c.Guardrail.Profiles[profile]; ok && profile != "" {
		overlay = p.Sandbox
	}
	view.base, view.overlay = base, overlay
	if overlay != nil {
		view.Overlay = adminKeyMap(*overlay)
	}
	view.Sources = map[string]string{}
	for key := range view.Organization {
		view.Sources[key] = sandboxapi.ExplainSourceOrganization
	}
	for key := range view.Overlay {
		// A profile that sets a key it tightens (or sets) is its source;
		// request_access is the only key it replaces.
		view.Sources[key] = sandboxapi.ExplainSourceProfile
	}
	if len(view.Sources) == 0 {
		view.Sources = nil
	}
	if sandboxFloorFor != nil {
		floor, digest, err := sandboxFloorFor(c, profile)
		switch {
		case err != nil:
			view.FloorError = err.Error()
		default:
			view.floor, view.hasFloor = floor, true
			view.Floor, view.Digest = adminKeyMap(floor), digest
			// A key the profile sets is the profile's only where the
			// resolved floor differs from the organization's value: an
			// intersected or unioned list, or a looser overlay value, that
			// leaves the organization's value standing is the organization's.
			for key := range view.Overlay {
				if orgValue, ok := view.Organization[key]; ok && reflect.DeepEqual(view.Floor[key], orgValue) {
					view.Sources[key] = sandboxapi.ExplainSourceOrganization
				}
				if _, inFloor := view.Floor[key]; !inFloor {
					// The overlay's value lost to the organization's unset
					// one (when_unavailable: alert under an unset base).
					view.Sources[key] = sandboxapi.ExplainSourceOrganization
				}
			}
			if len(floor.RequiredFor) > 0 && strings.TrimSpace(floor.WhenUnavailable) == "" {
				// An unset when_unavailable is refuse; show the winning
				// value and whose it is (GAP-0102).
				if view.Floor == nil {
					view.Floor = map[string]any{}
				}
				view.Floor["when_unavailable"] = config.OpenShellWhenUnavailableRefuse
				view.Sources["when_unavailable"] = sandboxapi.ExplainSourceOrganization
			}
		}
	}
	return view
}

// explainRegistration builds the administrator's explain of one registration.
func explainRegistration(c *config.Config, reg sandboxreg.Registration) registrationExplain {
	out := registrationExplain{Registration: reg, Policy: sandboxPolicyOf(c, reg.Profile)}
	if out.Policy.hasFloor {
		out.Managed = managedExplainOfFloor(reg, out.Policy.floor, out.Policy.Sources)
		if len(out.Managed.RequiredFor) > 0 {
			exempt := gateway.EnrollmentExemptFromSandbox(c.Enterprise.Enrollment, reg.UID, reg.UserName)
			// Preview the same gate as the user's explain. The gateway's
			// profile answer includes verified directory name matches.
			if !exempt && reg.UID != 0 && len(c.Enterprise.Enrollment.ExemptUsers) > 0 {
				_, _, _, resolved, err := enterprisePolicySandboxProfile(reg.UserName)
				if err == nil {
					exempt = resolved
				}
			}
			out.Managed.HostRunGate = gateway.RequireSandboxHostGate(out.Managed.RequiredFor, out.Managed.RequiredFor[0], exempt)
			out.Managed.EnrollmentExempt = out.Managed.HostRunGate == gateway.RequireSandboxHostRunExempt
		}
	}
	return out
}

// managedExplainOfFloor is the explain the registration's user is shown, from
// the floor F the registration runs under.
func managedExplainOfFloor(reg sandboxreg.Registration, f config.OpenShellAdminConfig, sources map[string]string) *sandboxapi.ManagedExplain {
	on := func(v *bool) bool { return v == nil || *v }
	updated := sandboxreg.PolicyUpdatedAt(reg)
	m := &sandboxapi.ManagedExplain{
		Profile: reg.Profile, Match: reg.ProfileMatch, MatchedGroup: reg.MatchedGroup, Provisional: reg.Provisional,
		Allowed: on(f.Allowed), RequiredFor: f.RequiredFor, WhenUnavailable: f.WhenUnavailable,
		AllowedHarnesses: f.AllowedHarnesses, AllowedCredentials: f.AllowedCredentials,
		EgressAllowOnly: f.EgressAllowOnly, EgressBlock: f.EgressBlock,
		UserApprovals: f.UserApprovals, AllowUnblock: on(f.AllowUnblock),
		WorkdirMode: reg.WorkdirMode, AllowMount: on(f.AllowMount) && reg.WorkdirMode != config.OpenShellWorkdirCopy,
		AllowHostPorts: on(f.AllowHostPorts), AllowYolo: on(f.AllowYolo),
		OnSilence: f.OnSilence, MaxSilenceAfter: f.MaxSilenceAfter, ProcessTree: f.ProcessTree != nil && *f.ProcessTree,
		DeleteStoppedAfter: f.DeleteStoppedAfter, PolicyDigest: reg.EffectiveDigest, UpdatedAt: updated,
		RequestAccess: f.RequestAccess, Driver: reg.Driver, DriverReason: reg.DriverReason,
		ForeignSandboxes: config.OpenShellForeignSandboxesStop,
		MCPIncluded:      reg.MCPKept,
	}
	if strings.EqualFold(strings.TrimSpace(f.ForeignSandboxes), config.OpenShellForeignSandboxesAlert) {
		m.ForeignSandboxes = config.OpenShellForeignSandboxesAlert
	}
	for _, s := range reg.MCPSkipped {
		m.MCPBlocked = append(m.MCPBlocked, sandboxapi.ManagedMCP{Name: s.Name, Reason: s.Reason})
	}
	if len(sources) > 0 {
		m.Sources = sources
	}
	return m
}

func printRegistrationExplain(w io.Writer, e registrationExplain, now time.Time) {
	r := e.Registration
	row := func(label, text string) { fmt.Fprintf(w, "  %-11s %s\n", label, sandboxapi.DisplayText(text)) }
	fmt.Fprintf(w, "Registration %s\n", sandboxapi.DisplayText(r.ID))
	row("User", fmt.Sprintf("%s (uid %d)", r.UserName, r.UID))
	row("State", firstNonEmptyString(r.State, "-")+revokedNote(r))
	row("Agent", strings.TrimSpace(r.Harness+" "+r.HarnessVersion)+" ("+firstNonEmptyString(r.TamperTier, "?")+" tier, hooks "+firstNonEmptyString(r.HookContract, "-")+")")
	row("Sandbox", firstNonEmptyString(r.SandboxName, "-")+", driver "+firstNonEmptyString(openshell.DriverChoiceText(r.Driver, r.DriverReason), "-")+", OpenShell "+firstNonEmptyString(r.OpenShell, "?")+" ("+firstNonEmptyString(r.InstallMode, "?")+" install), "+firstNonEmptyString(r.WorkdirMode, "copy")+" mode")
	row("Project", firstNonEmptyString(r.ProjectReal, "-"))
	match := firstNonEmptyString(r.Profile, "(organization floor)") + ", matched by " + firstNonEmptyString(r.ProfileMatch, "?")
	if r.MatchedGroup != "" {
		match += " " + r.MatchedGroup
	}
	if r.Provisional {
		match += ", provisional"
	}
	row("Profile", match)
	row("Digests", fmt.Sprintf("policy %s, profile %s, generation %d", firstNonEmptyString(r.EffectiveDigest, "-"), firstNonEmptyString(r.ProfileDigest, "-"), r.Generation))
	printRegistrationMCP(w, r)
	if e.Policy.FloorError != "" {
		row("Floor", "cannot be resolved: "+e.Policy.FloorError)
	}
	if e.Managed != nil {
		fmt.Fprintln(w, "\nWhat the user sees (defenseclaw sandbox policy explain):")
		for _, l := range sandboxcli.ManagedPolicyLines(e.Managed, now) {
			fmt.Fprintf(w, "  %-11s %s\n", sandboxapi.DisplayText(l.Label), sandboxapi.DisplayText(l.Text))
		}
	}
	printSandboxKeySources(w, e.Policy)
}

// printRegistrationMCP lists the user's MCP servers the registration kept and
// skipped, each skipped one with its reason (GAP-0554): nothing without a
// judged server.
func printRegistrationMCP(w io.Writer, r sandboxreg.Registration) {
	if len(r.MCPKept) == 0 && len(r.MCPSkipped) == 0 {
		return
	}
	names := func(list []string) string {
		if len(list) == 0 {
			return "none"
		}
		return strings.Join(list, ", ")
	}
	fmt.Fprintf(w, "  %-11s kept %s\n", "MCP", sandboxapi.DisplayText(names(r.MCPKept)))
	for _, s := range r.MCPSkipped {
		fmt.Fprintf(w, "  %-11s skipped %s (%s)\n", "", sandboxapi.DisplayText(s.Name), sandboxapi.DisplayText(s.Reason))
	}
}

func revokedNote(r sandboxreg.Registration) string {
	if r.State != sandboxreg.StateRevoked {
		return ""
	}
	return " (" + firstNonEmptyString(r.RevokedReason, "no reason recorded") + ")"
}

// printSandboxKeySources lists each sandbox key with its source.
func printSandboxKeySources(w io.Writer, p sandboxPolicyView) {
	if len(p.Sources) == 0 {
		return
	}
	keys := make([]string, 0, len(p.Sources))
	for k := range p.Sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintln(w, "\nSources (organization = openshell.admin for everyone, profile = this profile's sandbox section):")
	for _, k := range keys {
		fmt.Fprintf(w, "  %-26s %s\n", k, p.Sources[k])
	}
}

// addSandboxToProfileExplain adds effective.sandbox to the gateway's
// profile-explain answer: the sandbox keys of the matched profile with their
// sources. Only an answer that matched a subject (a profile name, even "")
// gets it; an answer the CLI cannot decode is returned as it came.
func addSandboxToProfileExplain(answer json.RawMessage, c *config.Config) json.RawMessage {
	var doc map[string]any
	if json.Unmarshal(answer, &doc) != nil || doc == nil || c == nil {
		return answer
	}
	effective, _ := doc["effective"].(map[string]any)
	if effective == nil {
		return answer
	}
	if !sandboxPolicyConfigured(c) {
		// Nothing sandbox-related is configured: leave the answer as it is.
		return answer
	}
	profile, _ := doc["profile"].(string)
	effective["sandbox"] = sandboxPolicyOf(c, profile)
	out, err := json.Marshal(doc)
	if err != nil {
		return answer
	}
	return out
}
