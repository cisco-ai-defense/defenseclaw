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
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Machine policy codes in the lifecycle result.
const (
	codeMachinePolicy           = "machine_policy_failed"
	codeMachinePolicyIncomplete = "machine_policy_incomplete"
	codePerUserHooks            = "per_user_hooks_remaining"
	// codeClaudeVersionFloorMissing names DefenseClaw's Claude Code version
	// floor drop-in as wanted but absent. It is a warning, not a verify
	// failure: the hooks are in place, and the floor stops no build older
	// than 2.1.163, which predates the setting.
	codeClaudeVersionFloorMissing = "claude_version_floor_missing"
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
	return opts, opts.Validate()
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
	return !sameStrings(coveredMachinePolicy(p.machinePolicy, result), p.machinePolicy) ||
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
// config without writing.
func (l *lifecycle) describeMachinePolicy(record *Deployment) {
	env, r := l.env, l.result
	raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		return
	}
	validated, err := env.validateConfig(raw)
	if err != nil {
		return
	}
	l.warnNoConnectorsEnabled(validated)
	intended, err := env.MachinePolicy.Intended(validated.Loaded)
	if err != nil {
		r.AddWarning(codeMachinePolicy, err.Error())
		return
	}
	result, verifyErr := env.MachinePolicy.Verify(validated.Loaded)
	if isCoded(verifyErr, codeMachinePolicy) {
		r.AddWarning(codeMachinePolicy, verifyErr.Error())
		return
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
	for index, name := range removed {
		message := fmt.Sprintf(
			"vendor machine policy for %s no longer carries the DefenseClaw hooks the last transaction placed, so %s runs without them; run `%s` to restore them",
			machinePolicyLabel(name, result), name, env.lifecycleCommand("repair"))
		if index == 0 && verifyErr != nil {
			message += " (" + verifyErr.Error() + ")"
		}
		r.AddWarning(codeMachinePolicyIncomplete, message)
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
}

// codeNoConnectorsEnabled names a deployment whose config enables no
// connector although the enumerator found users to protect.
const codeNoConnectorsEnabled = "no_connectors_enabled"

// warnNoConnectorsEnabled reports a config without an enabled
// guardrail.connectors entry on a host with eligible users: the enumerator
// publishes no target for them, and status would otherwise read coverage and
// security complete with 0 targets.
func (l *lifecycle) warnNoConnectorsEnabled(validated *validatedConfig) {
	env, r := l.env, l.result
	if len(validated.Connectors) > 0 {
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
	r.AddWarning(codeNoConnectorsEnabled, fmt.Sprintf(
		"the enumerator found %d eligible %s, but config.yaml enables no guardrail.connectors entry, so DefenseClaw protects no agent; enable the connectors to protect (for example guardrail.connectors.claudecode: {enabled: true}) and run `%s`",
		len(record.Accounts), users, env.lifecycleCommand("ensure")))
	r.SecurityComplete = false
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
