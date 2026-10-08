// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Machine policy codes in the lifecycle result.
const (
	codeMachinePolicy           = "machine_policy_failed"
	codeMachinePolicyIncomplete = "machine_policy_incomplete"
	codePerUserHooks            = "per_user_hooks_remaining"
	// codePerUserState names an enrolled account whose DefenseClaw
	// per-user state an uninstall --purge could not remove.
	codePerUserState = "per_user_state_remaining"
	// codeClaudeVersionFloorMissing names DefenseClaw's Claude Code version
	// floor drop-in as wanted but absent. It is a warning, not a verify
	// failure: the hooks are in place, and the floor stops no build older
	// than 2.1.163, which predates the setting.
	codeClaudeVersionFloorMissing = "claude_version_floor_missing"
	// codeMachinePolicyOff names an enabled connector whose machine policy
	// ownership is off: its sessions run without DefenseClaw's hooks. It is
	// a warning, not a verify failure: the administrator chose it.
	codeMachinePolicyOff = "machine_policy_off"
)

// MachinePolicyManager publishes, verifies and removes DefenseClaw's hooks
// in vendor machine policy (internal/enterprisepolicy). The lifecycle is
// the only writer on unix: it publishes inside every install, upgrade,
// repair and ensure transaction and removes DefenseClaw's entries on
// uninstall. Tests substitute a fake or a rooted real manager.
type MachinePolicyManager interface {
	// Intended lists the machine-policy connectors cfg asks for.
	Intended(cfg *config.Config) ([]string, error)
	Publish(cfg *config.Config) (enterprisepolicy.Result, error)
	Verify(cfg *config.Config) (enterprisepolicy.Result, error)
	RemoveAll() (enterprisepolicy.Result, error)
}

type policyManager struct {
	env *Env
	// skipTrust disables enterprisepolicy's ancestor ownership checks; only
	// rooted test environments set it.
	skipTrust bool
}

func newMachinePolicyManager(env *Env) MachinePolicyManager {
	return &policyManager{env: env}
}

// options maps the standalone layout onto the (possibly rooted) host. The
// hook binary stays canonical: it is the command written into vendor
// policy, not a file this process opens.
func (m *policyManager) options(cfg *config.Config) (enterprisepolicy.Options, error) {
	env := m.env
	var opts enterprisepolicy.Options
	if cfg == nil {
		opts = enterprisepolicy.LayoutOptions(env.Layout, "", "")
	} else {
		var err error
		if opts, err = enterprisepolicy.StandaloneOptions(env.Layout, "", "", cfg); err != nil {
			return enterprisepolicy.Options{}, err
		}
	}
	opts.GOOS = env.GOOS
	opts.Root = env.Root
	opts.StateDir = env.P(opts.StateDir)
	opts.PublicPolicyPath = env.P(opts.PublicPolicyPath)
	// OpenCodePluginPath stays canonical: it is the path OpenCode's managed
	// config names; enterprisepolicy inspects it under Root.
	opts.SkipTrustChecks = m.skipTrust
	opts.Now = env.Now
	if cfg != nil {
		opts.CopilotUserHomes = m.enrolledHomes()
	}
	return opts, opts.Validate()
}

// enrolledHomes are the eligible accounts' homes from the enumerator's
// root-only record (under Root in tests); the Copilot VS Code lock gate
// checks each for DefenseClaw's plugin. An unreadable record is no homes,
// which keeps the lock off.
func (m *policyManager) enrolledHomes() []string {
	return m.env.accountHomes(enterprisehooks.UnixEligibleAccountsPath(m.env.Layout.ManifestPath))
}

// accountHomes are the homes (under Root) in a root-only record in the
// eligible-accounts format: the enumerator's eligible accounts or the
// guardian's VS Code Local accounts. An unreadable record is no homes.
func (env *Env) accountHomes(recordPath string) []string {
	data, err := readBounded(env.P(recordPath), maxInputBytes)
	if err != nil {
		return nil
	}
	var record struct {
		Accounts []struct {
			Home string `json:"home"`
		} `json:"accounts"`
	}
	if json.Unmarshal(data, &record) != nil {
		return nil
	}
	homes := []string{}
	for _, account := range record.Accounts {
		if home := strings.TrimSpace(account.Home); home != "" {
			homes = append(homes, env.P(home))
		}
	}
	return homes
}

func (m *policyManager) Intended(cfg *config.Config) ([]string, error) {
	opts, err := m.options(cfg)
	if err != nil {
		return nil, err
	}
	// Every transaction renders the managed OpenCode plugin with the
	// deployment's files before it publishes, so the plan puts OpenCode on
	// machine policy even on the first install, before the file exists.
	opts.OpenCodePluginPlanned = true
	return enterprisepolicy.MachinePolicyConnectors(opts, enterprisepolicy.StandaloneConnectors(cfg)), nil
}

func (m *policyManager) Publish(cfg *config.Config) (enterprisepolicy.Result, error) {
	opts, err := m.options(cfg)
	if err != nil {
		return enterprisepolicy.Result{}, &codedError{code: codeMachinePolicy, err: err}
	}
	return enterprisepolicy.Publish(opts, enterprisepolicy.StandaloneConnectors(cfg))
}

func (m *policyManager) Verify(cfg *config.Config) (enterprisepolicy.Result, error) {
	opts, err := m.options(cfg)
	if err != nil {
		return enterprisepolicy.Result{}, &codedError{code: codeMachinePolicy, err: err}
	}
	return enterprisepolicy.VerifyAll(opts, enterprisepolicy.StandaloneConnectors(cfg))
}

func (m *policyManager) RemoveAll() (enterprisepolicy.Result, error) {
	opts, err := m.options(nil)
	if err != nil {
		return enterprisepolicy.Result{}, err
	}
	return enterprisepolicy.RemoveAll(opts)
}

// coveredMachinePolicy is the subset of intended whose DefenseClaw entries
// the result reports in place: the set the runtime descriptor records, so
// the gateway never treats a connector as machine-policy protected when its
// vendor file does not carry the hook.
func coveredMachinePolicy(intended []string, result enterprisepolicy.Result) []string {
	covered := map[string]bool{}
	for _, name := range result.MachinePolicyConnectors {
		covered[name] = true
	}
	out := []string{}
	for _, name := range intended {
		if covered[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// reportMachinePolicy copies per-connector machine policy states into the
// lifecycle result and warns for every intended connector that is not
// covered.
func reportMachinePolicy(r *enterprisestatus.Result, intended []string, result enterprisepolicy.Result, err error) {
	reportMachinePolicyExcept(r, intended, result, err, nil)
}

// reportMachinePolicyExcept is reportMachinePolicy for callers that report
// the connectors in skip themselves.
func reportMachinePolicyExcept(r *enterprisestatus.Result, intended []string, result enterprisepolicy.Result, err error, skip []string) {
	for _, state := range result.States {
		if state.Route != enterprisepolicy.RouteMachinePolicy {
			continue
		}
		r.MachinePolicy[state.Connector] = state.ToStatus()
	}
	missing := []string{}
	covered := coveredMachinePolicy(intended, result)
	for _, name := range intended {
		if !contains(covered, name) && !contains(skip, name) {
			missing = append(missing, machinePolicyLabel(name, result))
		}
	}
	if len(missing) > 0 {
		message := "DefenseClaw hooks are not in place in vendor machine policy for " + strings.Join(missing, ", ")
		if err != nil {
			message += ": " + err.Error()
		}
		for _, name := range intended {
			if !contains(covered, name) && !contains(skip, name) {
				for _, state := range result.States {
					if state.Connector == name && state.Ownership == config.MachinePolicyOwnershipVerifyOnly {
						message += fmt.Sprintf("; %s: ownership verify_only, so DefenseClaw never writes it: deploy the output of `enterprise policy export --connector %s` (missing_defenseclaw_hooks), then run ensure", name, name)
					}
				}
			}
		}
		r.AddWarning(codeMachinePolicyIncomplete, message)
	} else if err != nil && len(skip) == 0 {
		r.AddWarning(codeMachinePolicyIncomplete, err.Error())
	}
}

// machinePolicyLabel names a connector with the vendor machine-policy files
// DefenseClaw writes for it, for example "codex (/etc/codex/requirements.toml)".
func machinePolicyLabel(connector string, result enterprisepolicy.Result) string {
	for _, state := range result.States {
		if state.Connector == connector && state.Route == enterprisepolicy.RouteMachinePolicy && len(state.Paths) > 0 {
			return connector + " (" + strings.Join(state.Paths, ", ") + ")"
		}
	}
	return connector
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// isCoded reports whether err carries code.
func isCoded(err error, code string) bool {
	var coded *codedError
	return errors.As(err, &coded) && coded.code == code
}

// publishMachinePolicy places DefenseClaw's hooks in vendor machine policy
// for the plan's config. A connector whose vendor file cannot take the
// entry is reported (security_complete stays false) instead of failing the
// whole transaction: every other connector still gets protected, and the
// descriptor is re-rendered to name only the connectors actually covered.
// Invalid options fail the transaction.
func (l *lifecycle) publishMachinePolicy(p *plan, changed map[string]bool) error {
	env, r := l.env, l.result
	result, err := env.MachinePolicy.Publish(p.config.Loaded)
	if isCoded(err, codeMachinePolicy) {
		return err
	}
	l.machinePolicyErr = err
	reportMachinePolicy(r, p.intended, result, err)
	for _, state := range result.States {
		if state.Changed {
			l.noteChange("rewrote DefenseClaw's %s machine policy entries", state.Connector)
		}
	}
	covered := coveredMachinePolicy(p.intended, result)
	if sameStrings(covered, p.machinePolicy) {
		return nil
	}
	p.machinePolicy = covered
	p.render.MachinePolicy = covered
	data, err := env.renderDescriptor(p.render)
	if err != nil {
		return &codedError{code: codeApply, err: err}
	}
	for index := range p.files {
		file := &p.files[index]
		if file.Path != env.Layout.DescriptorPath {
			continue
		}
		if err := env.writeFileAtomic(env.P(file.Path), data, file.Mode, file.Owner); err != nil {
			return &codedError{code: codeApply, err: err}
		}
		file.Data = data
		file.SHA = sha256Bytes(data)
		if !changed[file.Path] {
			l.noteChange("rewrote %s", file.Path)
		}
		changed[file.Path] = true
		return nil
	}
	return &codedError{code: codeApply, err: errors.New("the plan has no runtime descriptor")}
}

// machinePolicyDrift reports whether the vendor machine policy no longer
// carries the entries the committed deployment recorded, so ensure must
// re-apply.
func (l *lifecycle) machinePolicyDrift(p *plan) bool {
	result, err := l.env.MachinePolicy.Verify(p.config.Loaded)
	if isCoded(err, codeMachinePolicy) {
		return true
	}
	// A connector whose hooks came back (the administrator deployed the
	// export of a verify_only file) is applied too, so the gateway uses them
	// (GAP-0536).
	return !sameStrings(coveredMachinePolicy(p.machinePolicy, result), p.machinePolicy) ||
		!sameStrings(coveredMachinePolicy(p.intended, result), p.machinePolicy) ||
		missingClaudeVersionFloor(result) != ""
}

// missingClaudeVersionFloor is DefenseClaw's Claude Code version floor
// drop-in when the result reports it wanted and absent, otherwise "".
func missingClaudeVersionFloor(result enterprisepolicy.Result) string {
	for _, state := range result.States {
		if state.Connector == enterprisepolicy.ConnectorClaudeCode && state.VersionFloor != nil && state.VersionFloor.Missing {
			return state.VersionFloor.Path
		}
	}
	return ""
}

// describeMachinePolicy reports the vendor machine policy of the installed
// config without writing. It returns the problems that fail both status
// and verify: enrolled users' guardian-owned hook files that are missing
// or modified.
func (l *lifecycle) describeMachinePolicy(record *Deployment) []string {
	env, r := l.env, l.result
	raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		return nil
	}
	validated, err := env.validateConfig(raw)
	if err != nil {
		return nil
	}
	l.warnNoConnectorsEnabled(validated)
	intended, err := env.MachinePolicy.Intended(validated.Loaded)
	if err != nil {
		r.AddWarning(codeMachinePolicy, err.Error())
		return nil
	}
	result, verifyErr := env.MachinePolicy.Verify(validated.Loaded)
	if isCoded(verifyErr, codeMachinePolicy) {
		r.AddWarning(codeMachinePolicy, verifyErr.Error())
		return nil
	}
	// A connector the last transaction placed that is gone from its vendor
	// file now is reported once, with the file and the command that puts it
	// back; the general "not in place" message covers the rest.
	var removed, unwanted []string
	if record != nil && record.MachinePolicyConnectors != nil {
		recorded := coveredMachinePolicy(record.MachinePolicyConnectors, result)
		for _, name := range intersectSorted(record.MachinePolicyConnectors, intended) {
			if !contains(recorded, name) {
				removed = append(removed, name)
			}
		}
		for _, name := range recorded {
			if !contains(intended, name) {
				unwanted = append(unwanted, name)
			}
		}
	}
	reportMachinePolicyExcept(r, intended, result, verifyErr, removed)
	// A connector whose DefenseClaw entries are gone from its vendor file runs
	// without hooks, so status fails on it as verify does (GAP-0529).
	var gone []string
	for index, name := range removed {
		message := fmt.Sprintf(
			"vendor machine policy for %s no longer carries the DefenseClaw hooks the last transaction placed, so %s runs without them; run `%s` to restore them",
			machinePolicyLabel(name, result), name, env.lifecycleCommand("repair"))
		if drift := driftConflicts(name, result); len(drift) > 0 {
			// The entries are in place, but agents cannot use them (a
			// directory users cannot read, a file mode) (GAP-0913).
			message = fmt.Sprintf("DefenseClaw hooks are in place in vendor machine policy for %s but do not protect %s: %s; run `%s` to restore them",
				machinePolicyLabel(name, result), name, strings.Join(drift, "; "), env.lifecycleCommand("repair"))
		}
		if export := env.verifyOnlyExport(name, result); export != "" {
			// repair never writes a file the administrator owns (GAP-0536).
			message = fmt.Sprintf("vendor machine policy for %s no longer carries the DefenseClaw hooks, so %s runs without them; %s",
				machinePolicyLabel(name, result), name, export)
		}
		if index == 0 && verifyErr != nil {
			message += " (" + verifyErr.Error() + ")"
		}
		r.AddWarning(codeMachinePolicyIncomplete, message)
		gone = append(gone, message)
	}
	// Hooks that came back after the last transaction left the connector out
	// (the administrator deployed the export of a verify_only file) are not
	// used until ensure applies them (GAP-0536).
	if record != nil && record.MachinePolicyConnectors != nil {
		for _, name := range coveredMachinePolicy(intended, result) {
			if !contains(record.MachinePolicyConnectors, name) {
				r.AddWarning(codeMachinePolicyIncomplete, fmt.Sprintf(
					"DefenseClaw hooks are in place in vendor machine policy for %s again, but the running deployment does not use them yet; run `%s` to apply them",
					machinePolicyLabel(name, result), env.lifecycleCommand(ActionEnsure)))
			}
		}
	}
	// DefenseClaw's entries in place protect nothing when a higher-precedence
	// source outranks them (a com.anthropic.claudecode or com.openai.codex
	// managed-preferences profile without the hooks) or the file carries a
	// conflicting value (Codex allow_managed_hooks_only flipped to false).
	// enterprise policy verify reports such a connector not covered; status
	// and verify said nothing while the agent ran without enforcement
	// (GAP-0534, GAP-0531). Version floor conflicts stay
	// claude_version_floor_missing, which verify does not fail on.
	inPlace := coveredMachinePolicy(intended, result)
	for _, state := range result.States {
		if state.Route != enterprisepolicy.RouteMachinePolicy || state.Covered || !contains(inPlace, state.Connector) {
			continue
		}
		var reasons []string
		for _, conflict := range state.Conflicts {
			if !strings.HasPrefix(conflict, claudeVersionFloorConflict) {
				reasons = append(reasons, conflict)
			}
		}
		if len(reasons) == 0 && len(state.HigherPrecedence) > 0 {
			reasons = append(reasons, strings.Join(state.HigherPrecedence, ", ")+" outranks them")
		}
		if len(reasons) == 0 {
			continue
		}
		r.AddWarning(codeMachinePolicyIncomplete, fmt.Sprintf(
			"DefenseClaw hooks are in place in vendor machine policy for %s but do not protect %s: %s",
			machinePolicyLabel(state.Connector, result), state.Connector, strings.Join(reasons, "; ")))
	}
	// ownership: off for a connector guardrail.connectors still enables
	// left status and verify fully green while its sessions ran without
	// DefenseClaw's hooks; only policy show said so (GAP-0922). OpenCode
	// keeps its per-user plugin under ownership: off.
	for _, state := range result.States {
		if state.Ownership != config.MachinePolicyOwnershipOff || state.Connector == enterprisepolicy.ConnectorOpenCode ||
			enterprisepolicy.RouteFor(state.Connector, env.GOOS) != enterprisepolicy.RouteMachinePolicy {
			continue
		}
		r.AddWarning(codeMachinePolicyOff, fmt.Sprintf(
			"guardrail.connectors enables %s, but enterprise.machine_policy.connectors.%s.ownership is off: DefenseClaw neither writes nor checks its machine policy and installs no per-user hooks for it, so %s sessions run without DefenseClaw's hooks; set ownership to merge or verify_only to protect it, or disable the connector",
			state.Connector, state.Connector, state.Connector))
	}
	for _, name := range unwanted {
		r.AddWarning(codeMachinePolicyIncomplete, fmt.Sprintf(
			"vendor machine policy for %s still carries DefenseClaw hooks, but the installed config.yaml no longer asks for them; run `%s` to apply the config",
			machinePolicyLabel(name, result), env.lifecycleCommand("ensure")))
	}
	if path := missingClaudeVersionFloor(result); path != "" {
		r.AddWarning(codeClaudeVersionFloorMissing, fmt.Sprintf(
			"DefenseClaw's Claude Code version floor %s is missing; `%s` (or reconcile or repair) writes it back",
			path, env.lifecycleCommand("ensure")))
	}
	// A per-user file the guardian owns (Copilot's VS Code Local hook file)
	// that a user deleted or edited leaves that agent surface unguarded
	// until the guardian rewrites it, so status and verify both fail on it
	// (WIN-R1-25, #1055), as on managed Windows. Two cases are not drift:
	// a home that no longer exists (a deleted account, which
	// guardian_target_account_removed reports; GAP-1209), and an account
	// the guardian has not written the file for yet (a fresh install or a
	// newly enrolled user; GAP-1267), which is a warning until its pass.
	homeOf := map[string]string{}
	for _, home := range env.accountHomes(enterprisehooks.UnixEligibleAccountsPath(env.Layout.ManifestPath)) {
		homeOf[enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)] = home
	}
	// The guardian keeps its record in its data directory (GAP-1761); an
	// earlier build left it next to the manifest.
	written := map[string]bool{}
	for _, record := range []string{
		filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixCopilotVSCodeAccountsFileName),
		enterprisehooks.UnixCopilotVSCodeAccountsPath(env.Layout.ManifestPath),
	} {
		for _, home := range env.accountHomes(record) {
			written[home] = true
		}
	}
	var drift []string
	for _, state := range result.States {
		var changed, pending []string
		for _, path := range state.UserFileDrift {
			home, known := homeOf[path]
			if known {
				if _, err := os.Lstat(home); errors.Is(err, os.ErrNotExist) {
					continue
				}
			}
			if known && !written[home] {
				pending = append(pending, path)
				continue
			}
			changed = append(changed, path)
		}
		if len(pending) > 0 {
			r.AddWarning(codeGuardianUserFilePending, fmt.Sprintf(
				"DefenseClaw's %s hook file is not written yet for %d newly enrolled user(s): %s; the hook guardian writes it on its first pass for them",
				state.Connector, len(pending), firstPaths(pending)))
		}
		if len(changed) == 0 {
			continue
		}
		drift = append(drift, fmt.Sprintf(
			"DefenseClaw's %s hook file is missing or modified for %d enrolled user(s): %s; the hook guardian rewrites it on its next pass",
			state.Connector, len(changed), firstPaths(changed)))
		r.SecurityComplete = false
	}
	return append(gone, drift...)
}

// driftConflicts are the conflicts of a connector whose DefenseClaw entries
// are in its vendor file but drifted from what a publish writes.
func driftConflicts(connector string, result enterprisepolicy.Result) []string {
	for _, state := range result.States {
		if state.Connector == connector && state.Drift && state.OwnedEntries > 0 {
			return state.Conflicts
		}
	}
	return nil
}

// claudeVersionFloorConflict starts every Claude Code version floor conflict.
const claudeVersionFloorConflict = "Claude Code version floor: "

// verifyOnlyExport is the remedy for a connector whose vendor file DefenseClaw
// only verifies (ownership verify_only): the administrator deploys the
// export, then runs ensure so the deployment uses the hooks again. It is ""
// for a file DefenseClaw writes, which repair restores.
func (e *Env) verifyOnlyExport(connector string, result enterprisepolicy.Result) string {
	for _, state := range result.States {
		if state.Connector == connector && state.Ownership == config.MachinePolicyOwnershipVerifyOnly {
			return fmt.Sprintf("missing_defenseclaw_hooks: DefenseClaw does not write this file (ownership: verify_only), so repair does not restore it; deploy the output of `%s enterprise policy export --connector %s` through your policy tool, then run `%s`",
				filepath.Join(e.Layout.BinDir, binGateway), connector, e.lifecycleCommand(ActionEnsure))
		}
	}
	return ""
}

// machinePolicyIncomplete reports whether the result warns that a vendor
// machine policy does not protect a connector, which security_complete
// cannot be while it is so.
func machinePolicyIncomplete(r *enterprisestatus.Result) bool {
	return hasMessageCode(r.Warnings, codeMachinePolicyIncomplete)
}

// codeGuardianUserFilePending names enrolled users whose guardian-owned
// per-user hook file the guardian has not written yet.
const codeGuardianUserFilePending = "guardian_user_file_pending"

// firstPaths lists up to five paths and counts the rest.
func firstPaths(paths []string) string {
	if len(paths) > 5 {
		paths = append(append([]string{}, paths[:5]...), fmt.Sprintf("and %d more", len(paths)-5))
	}
	return strings.Join(paths, ", ")
}

// codeNoConnectorsEnabled names a deployment whose config enables no
// connector although the enumerator found users to protect.
const codeNoConnectorsEnabled = "no_connectors_enabled"

// warnNoConnectorsEnabled reports a config that enrols no connector on a
// host with eligible users: the enumerator publishes no target for them, and
// status would otherwise read coverage and security complete with 0 targets.
// verify fails on it (GAP-0221). The connectors counted are the enumerator's
// own set, so the singular guardrail.connector the per-user CLI writes counts
// unless guardrail.connectors disables it (GAP-0263).
func (l *lifecycle) warnNoConnectorsEnabled(validated *validatedConfig) {
	env, r := l.env, l.result
	if len(enterprisehooks.EffectiveUnixHookConnectors(validated.Loaded, connector.NewDefaultRegistry())) > 0 {
		return
	}
	data, err := readBounded(env.P(enterprisehooks.UnixEligibleAccountsPath(env.Layout.ManifestPath)), maxInputBytes)
	if err != nil {
		return
	}
	var record struct {
		Accounts []json.RawMessage `json:"accounts"`
	}
	if json.Unmarshal(data, &record) != nil || len(record.Accounts) == 0 {
		return
	}
	users := "users"
	if len(record.Accounts) == 1 {
		users = "user"
	}
	// Name what counts and what was ignored: an administrator with an
	// openclaw entry read "enables no guardrail.connectors entry" as wrong
	// (GAP-0272).
	ignored := ""
	if entries := ignoredConnectorEntries(validated.Loaded, env.GOOS); len(entries) > 0 {
		ignored = " (ignored: " + strings.Join(entries, ", ") + ")"
	}
	r.AddWarning(codeNoConnectorsEnabled, fmt.Sprintf(
		"the enumerator found %d eligible %s, but config.yaml enables no connector the managed deployment protects in guardrail.connector or guardrail.connectors%s, so DefenseClaw protects no agent; enable the connectors to protect (for example guardrail.connectors.claudecode: {}) and run `%s`",
		len(record.Accounts), users, ignored, env.lifecycleCommand("ensure")))
	r.SecurityComplete = false
}

// ignoredConnectorEntries lists the guardrail.connector and
// guardrail.connectors entries of a config whose effective connector set is
// empty, each with why it does not count.
func ignoredConnectorEntries(cfg *config.Config, goos string) []string {
	if cfg == nil {
		return nil
	}
	names := []string{cfg.Guardrail.Connector}
	for name := range cfg.Guardrail.Connectors {
		names = append(names, name)
	}
	platform := map[string]string{"linux": "Linux", "darwin": "macOS"}[goos]
	seen := map[string]bool{}
	out := []string{}
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		if !cfg.Guardrail.EffectiveEnabled(name) {
			out = append(out, key+" (enabled: false)")
		} else {
			out = append(out, key+" (not supported by managed enterprise on "+platform+")")
		}
	}
	sort.Strings(out)
	return out
}

func intersectSorted(values, allowed []string) []string {
	out := []string{}
	for _, value := range values {
		if contains(allowed, value) && !contains(out, value) {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

// republishMachinePolicy repairs DefenseClaw's vendor machine policy
// entries between transactions (the reconcile action). It never rewrites
// the descriptor or restarts services: when the covered set changed, the
// result tells the administrator to run ensure.
func (l *lifecycle) republishMachinePolicy(record *Deployment) {
	env, r := l.env, l.result
	raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		r.AddWarning(codeMachinePolicy, "read config: "+err.Error())
		return
	}
	validated, err := env.validateConfig(raw)
	if err != nil {
		r.AddWarning(codeMachinePolicy, err.Error())
		return
	}
	intended, err := env.MachinePolicy.Intended(validated.Loaded)
	if err != nil {
		r.AddWarning(codeMachinePolicy, err.Error())
		return
	}
	result, publishErr := env.MachinePolicy.Publish(validated.Loaded)
	if isCoded(publishErr, codeMachinePolicy) {
		r.AddWarning(codeMachinePolicy, publishErr.Error())
		return
	}
	reportMachinePolicy(r, intended, result, publishErr)
	if record != nil && record.MachinePolicyConnectors != nil &&
		!sameStrings(coveredMachinePolicy(intended, result), intersectSorted(record.MachinePolicyConnectors, intended)) {
		r.AddWarning(codeMachinePolicyIncomplete, "the machine-policy connectors in place differ from the runtime descriptor; run ensure")
	}
}
