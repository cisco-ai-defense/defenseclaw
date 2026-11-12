// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The runtime keys of SandboxAdminConfig (PLAN §7.3): which sandbox
// runtimes a subject's agents use, and how an Agent Substrate actor runs.
// runtimes applies on computers and in clusters. sandbox_class,
// idle_suspend_after, unattended_asks, ask_timeout and actor_secrets are
// Substrate keys: openshell.admin refuses them, and a profile's values
// apply to actors only. The host sandbox keys (SandboxHostOnlyKeys) are
// refused in substrate.admin and ignored for actors.

// Sandbox runtimes (runtimes values).
const (
	SandboxRuntimeOpenShell = "openshell"
	SandboxRuntimeSubstrate = "substrate"
)

// Limits of the runtime keys.
const (
	// SandboxMinIdleSuspendAfter is the shortest idle_suspend_after.
	SandboxMinIdleSuspendAfter = time.Minute
	// SandboxMinAskTimeout and SandboxMaxAskTimeout bound ask_timeout.
	SandboxMinAskTimeout = time.Minute
	SandboxMaxAskTimeout = 24 * time.Hour
	// sandboxMaxActorSecrets bounds actor_secrets.
	sandboxMaxActorSecrets = 64
)

// sandboxActorSecretName is an actor_secrets entry: a key of the callout's
// actor-secrets Secret, so the callout's file name rule.
var sandboxActorSecretName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// SandboxSubstrateOnlyKeys are the floor keys only Agent Substrate actors
// read; openshell.admin refuses them.
var SandboxSubstrateOnlyKeys = []string{"sandbox_class", "idle_suspend_after", "unattended_asks", "ask_timeout", "actor_secrets"}

// SandboxHostOnlyKeys are the floor keys only a sandbox on a computer
// reads (mounts, host ports, the process tree, the KVM driver fallback and
// the working directory); substrate.admin refuses them.
var SandboxHostOnlyKeys = []string{"allow_mount", "allow_host_ports", "process_tree", "driver_fallback", "require_copy_for", "locked workdir.*"}

// validateRuntimeKeys checks the runtime keys of one floor section.
func (a *SandboxAdminConfig) validateRuntimeKeys(prefix string) error {
	var errs []error
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	if a.Runtimes != nil && len(a.Runtimes) == 0 {
		check(fmt.Errorf("%s.runtimes: an empty list is refused; leave the key out for no constraint", prefix))
	}
	for i, rt := range a.Runtimes {
		switch rt {
		case SandboxRuntimeOpenShell, SandboxRuntimeSubstrate:
		default:
			check(fmt.Errorf("%s.runtimes[%d]: %q must be openshell or substrate", prefix, i, rt))
		}
	}
	check(validateOpenShellEnum(prefix+".sandbox_class", a.SandboxClass, true, SubstrateSandboxGVisor, SubstrateSandboxMicroVM))
	check(validateOpenShellEnum(prefix+".unattended_asks", a.UnattendedAsks, true, SubstrateAsksDeny, SubstrateAsksQueue))
	check(validateGoDuration(prefix+".idle_suspend_after", a.IdleSuspendAfter, SandboxMinIdleSuspendAfter, 0, "1m", "30m"))
	check(validateGoDuration(prefix+".ask_timeout", a.AskTimeout, SandboxMinAskTimeout, SandboxMaxAskTimeout, "1m", "30m"))
	if a.ActorSecrets != nil && len(a.ActorSecrets) == 0 {
		check(fmt.Errorf("%s.actor_secrets: an empty list is refused; leave the key out to expose no value", prefix))
	}
	if len(a.ActorSecrets) > sandboxMaxActorSecrets {
		check(fmt.Errorf("%s.actor_secrets: at most %d entries", prefix, sandboxMaxActorSecrets))
	}
	for i, name := range a.ActorSecrets {
		if !sandboxActorSecretName.MatchString(name) {
			check(fmt.Errorf("%s.actor_secrets[%d]: %q must be a secret key (letters, digits, \".\", \"_\" and \"-\")", prefix, i, name))
		}
	}
	return errors.Join(errs...)
}

// validateGoDuration checks a Go duration key between minimum and maximum
// (0 = no maximum); "" is unset.
func validateGoDuration(field, value string, minimum, maximum time.Duration, minText, example string) error {
	if value == "" {
		return nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(value))
	switch {
	case err != nil:
		return fmt.Errorf("%s %q must be a Go duration such as %s", field, value, example)
	case d < minimum:
		return fmt.Errorf("%s %q must be at least %s", field, value, minText)
	case maximum > 0 && d > maximum:
		return fmt.Errorf("%s %q must be at most %s", field, value, maximum)
	}
	return nil
}

// hostScopeError refuses the Substrate keys in openshell.admin: a computer
// runs no actor, so they would silently do nothing there.
func (a *SandboxAdminConfig) hostScopeError(prefix string) error {
	var errs []error
	for _, key := range a.setSubstrateOnlyKeys() {
		errs = append(errs, fmt.Errorf("%s.%s is an Agent Substrate key; set it in substrate.admin or a guardrail profile's sandbox section", prefix, key))
	}
	return errors.Join(errs...)
}

// substrateScopeError refuses the host sandbox keys in substrate.admin: an
// actor has no host mounts, host ports, process tree, KVM driver or local
// working directory.
func (a *SandboxAdminConfig) substrateScopeError(prefix string) error {
	var errs []error
	for _, key := range a.setHostOnlyKeys() {
		errs = append(errs, fmt.Errorf("%s.%s is a host sandbox key; Agent Substrate actors do not use it", prefix, key))
	}
	return errors.Join(errs...)
}

func (a *SandboxAdminConfig) setSubstrateOnlyKeys() []string {
	var out []string
	for key, set := range map[string]bool{
		"sandbox_class": a.SandboxClass != "", "idle_suspend_after": a.IdleSuspendAfter != "",
		"unattended_asks": a.UnattendedAsks != "", "ask_timeout": a.AskTimeout != "", "actor_secrets": a.ActorSecrets != nil,
	} {
		if set {
			out = append(out, key)
		}
	}
	return orderedLike(out, SandboxSubstrateOnlyKeys)
}

func (a *SandboxAdminConfig) setHostOnlyKeys() []string {
	var out []string
	if a.AllowMount != nil {
		out = append(out, "allow_mount")
	}
	if a.AllowHostPorts != nil {
		out = append(out, "allow_host_ports")
	}
	if a.ProcessTree != nil {
		out = append(out, "process_tree")
	}
	if a.DriverFallback != "" {
		out = append(out, "driver_fallback")
	}
	if len(a.RequireCopyFor) > 0 {
		out = append(out, "require_copy_for")
	}
	for i, key := range a.Locked {
		if strings.HasPrefix(strings.TrimSpace(key), "workdir.") {
			out = append(out, fmt.Sprintf("locked[%d] (%s)", i, strings.TrimSpace(key)))
		}
	}
	return out
}

func orderedLike(set, order []string) []string {
	out := make([]string, 0, len(set))
	for _, key := range order {
		if slices.Contains(set, key) {
			out = append(out, key)
		}
	}
	return out
}

// tightenRuntimeKeys combines the runtime keys of overlay into out
// (TightenSandboxAdmin): runtimes and actor_secrets intersect;
// sandbox_class microvm wins; unattended_asks deny wins; idle_suspend_after
// and ask_timeout take the shortest. Runtimes that leave nothing is a
// *SandboxPolicyContradictionError; actor_secrets that leave nothing
// expose no value.
func tightenRuntimeKeys(out *SandboxAdminConfig, o SandboxAdminConfig) error {
	switch {
	case o.Runtimes == nil:
	case out.Runtimes == nil:
		out.Runtimes = slices.Clone(o.Runtimes)
	default:
		var both []string
		for _, rt := range out.Runtimes {
			if containsFold(o.Runtimes, rt) && !containsFold(both, rt) {
				both = append(both, rt)
			}
		}
		if len(both) == 0 {
			return emptyIntersection("runtimes", o.Runtimes, out.Runtimes, "runtime")
		}
		out.Runtimes = both
	}
	switch {
	case o.ActorSecrets == nil:
	case out.ActorSecrets == nil:
		out.ActorSecrets = slices.Clone(o.ActorSecrets)
	default:
		both := []string{}
		for _, name := range out.ActorSecrets {
			if slices.Contains(o.ActorSecrets, name) && !slices.Contains(both, name) {
				both = append(both, name)
			}
		}
		out.ActorSecrets = both
	}
	if sandboxClassRank(o.SandboxClass) > sandboxClassRank(out.SandboxClass) {
		out.SandboxClass = strings.ToLower(o.SandboxClass)
	}
	if v := strings.ToLower(o.UnattendedAsks); v == SubstrateAsksDeny || (v != "" && out.UnattendedAsks == "") {
		out.UnattendedAsks = v
	}
	out.IdleSuspendAfter = minGoDuration(out.IdleSuspendAfter, o.IdleSuspendAfter)
	out.AskTimeout = minGoDuration(out.AskTimeout, o.AskTimeout)
	return nil
}

func containsFold(list []string, v string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(v)) })
}

func sandboxClassRank(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case SubstrateSandboxMicroVM:
		return 2
	case SubstrateSandboxGVisor:
		return 1
	}
	return 0
}

func minGoDuration(a, b string) string {
	switch {
	case b == "":
		return a
	case a == "":
		return b
	}
	da, errA := time.ParseDuration(strings.TrimSpace(a))
	db, errB := time.ParseDuration(strings.TrimSpace(b))
	if errA == nil && errB == nil && db < da {
		return b
	}
	return a
}

// AllowsRuntime reports whether the floor lets an agent use runtime rt
// (openshell or substrate): unset runtimes allows both.
func (a SandboxAdminConfig) AllowsRuntime(rt string) bool {
	return a.Runtimes == nil || containsFold(a.Runtimes, rt)
}

// SubstrateOnly reports a floor whose agents may run on Agent Substrate
// only (runtimes: [substrate]): a required_for host run is pointed to
// `defenseclaw substrate run`, and an OpenShell sandbox is refused.
func (a SandboxAdminConfig) SubstrateOnly() bool {
	return a.Runtimes != nil && !a.AllowsRuntime(SandboxRuntimeOpenShell) && a.AllowsRuntime(SandboxRuntimeSubstrate)
}

// EffectiveSandboxClass is the stronger of the floor's sandbox_class and
// def (the cluster's substrate.default_sandbox_class): a profile requires
// an isolation class (D7), it never weakens the cluster's.
func (a SandboxAdminConfig) EffectiveSandboxClass(def string) string {
	if sandboxClassRank(a.SandboxClass) > sandboxClassRank(def) {
		return strings.ToLower(a.SandboxClass)
	}
	return strings.ToLower(def)
}

// SandboxClassSatisfies reports whether an actor running in class meets a
// floor that requires required ("" = any class): microvm meets both.
func SandboxClassSatisfies(class, required string) bool {
	return sandboxClassRank(class) >= sandboxClassRank(required)
}

// EffectiveIdleSuspendAfter is the floor's idle_suspend_after (substrate.admin
// tightened by the actor's profiles), else def, the cluster's
// substrate.idle_suspend_after (0 = off).
func (a SandboxAdminConfig) EffectiveIdleSuspendAfter(def time.Duration) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(a.IdleSuspendAfter)); a.IdleSuspendAfter != "" && err == nil && d > 0 {
		return d
	}
	return def
}

// EffectiveUnattendedAsks is deny or queue for an unattended actor: the
// floor's unattended_asks (deny wins between substrate.admin and the
// profiles), else def, the cluster's substrate.unattended.asks (deny when
// unset, D12).
func (a SandboxAdminConfig) EffectiveUnattendedAsks(def string) string {
	v := strings.ToLower(strings.TrimSpace(a.UnattendedAsks))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(def))
	}
	if v == SubstrateAsksQueue {
		return SubstrateAsksQueue
	}
	return SubstrateAsksDeny
}

// EffectiveAskTimeout is the floor's ask_timeout (the shortest of
// substrate.admin and the profiles), else def, the cluster's
// substrate.unattended.ask_timeout. A queued ask still open then is denied.
func (a SandboxAdminConfig) EffectiveAskTimeout(def time.Duration) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(a.AskTimeout)); a.AskTimeout != "" && err == nil && d > 0 {
		return d
	}
	return def
}

// validateSubstrateProfiles checks, for a cluster config (substrate.admin
// or the substrate section in use), every profile actors can take: a
// launcher_atespaces profile and every profile_assignments entry with
// match.substrate. Each must be defined (or "default") and tighten
// substrate.admin without a contradiction.
func (c *Config) validateSubstrateProfiles() error {
	if c == nil || (!c.Substrate.Enabled && len(c.Substrate.LauncherAtespaces) == 0) {
		return nil
	}
	var names []string
	for _, name := range sortedKeys(c.Substrate.LauncherAtespaces) {
		names = append(names, name)
	}
	for _, a := range c.Guardrail.ProfileAssignments {
		if !a.Match.Substrate.Empty() && !slices.Contains(names, a.Profile) {
			names = append(names, a.Profile)
		}
	}
	var errs []error
	for _, name := range names {
		p, ok := c.Guardrail.Profiles[name]
		if !ok {
			// A launcher profile without a definition takes substrate.admin
			// alone, as the controller resolves it.
			continue
		}
		if _, err := TightenSandboxAdmin(c.Substrate.Admin, p.Sandbox); err != nil {
			errs = append(errs, fmt.Errorf("guardrail.profiles[%q].sandbox: combined with substrate.admin: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
