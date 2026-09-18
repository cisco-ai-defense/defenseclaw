// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var acpStableNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

const (
	maxACPBindings      = 128
	maxACPProfiles      = 128
	maxACPDeniedMethods = 256
)

// Validate checks the security-relevant relationships in the ACP policy. The
// JSON schema owns shape and size limits; this method also protects legacy YAML
// loading and ensures bindings cannot silently select missing profiles.
func (a *ACPConfig) Validate() error {
	if a == nil {
		return nil
	}
	if err := validateACPMode(a.Mode, true); err != nil {
		return fmt.Errorf("mode: %w", err)
	}
	if len(a.Clients) > maxACPBindings || len(a.Agents) > maxACPBindings || len(a.Profiles) > maxACPProfiles {
		return fmt.Errorf("ACP clients, agents, and profiles are limited to %d entries each", maxACPBindings)
	}
	if a.DefaultProfile != "" {
		if err := validateACPStableName("default_profile", a.DefaultProfile); err != nil {
			return err
		}
		if _, ok := a.Profiles[a.DefaultProfile]; !ok {
			return fmt.Errorf("default_profile %q is not defined in profiles", a.DefaultProfile)
		}
	}
	if a.Enabled && strings.TrimSpace(a.DefaultProfile) == "" {
		return fmt.Errorf("default_profile is required when ACP is enabled")
	}
	pinProfileRequired := len(a.Bindings) == 0
	if err := validateACPBindings("clients", a.Clients, a.Profiles, pinProfileRequired); err != nil {
		return err
	}
	if err := validateACPBindings("agents", a.Agents, a.Profiles, pinProfileRequired); err != nil {
		return err
	}
	if len(a.Bindings) > maxACPBindings {
		return fmt.Errorf("ACP bindings are limited to %d entries", maxACPBindings)
	}
	if err := validateACPPairBindings(*a); err != nil {
		return err
	}

	profileNames := sortedACPKeys(a.Profiles)
	for _, name := range profileNames {
		if err := validateACPStableName("profile", name); err != nil {
			return err
		}
		profile := a.Profiles[name]
		if err := validateACPMode(profile.Mode, true); err != nil {
			return fmt.Errorf("profiles[%q].mode: %w", name, err)
		}
		failMode := strings.ToLower(strings.TrimSpace(profile.FailMode))
		switch failMode {
		case "", "open", "closed":
		default:
			return fmt.Errorf("profiles[%q].fail_mode: invalid value %q (want open or closed)", name, profile.FailMode)
		}
		effectiveMode := strings.TrimSpace(profile.Mode)
		if effectiveMode == "" {
			effectiveMode = strings.TrimSpace(a.Mode)
		}
		if effectiveMode == "" {
			effectiveMode = "observe"
		}
		expectedFailureMode := "open"
		if effectiveMode == "action" {
			expectedFailureMode = "closed"
		}
		if failMode != "" && failMode != expectedFailureMode {
			return fmt.Errorf(
				"profiles[%q].fail_mode must be %q when mode is %q",
				name, expectedFailureMode, effectiveMode,
			)
		}
		if err := validateACPNameList(name, "allowed_clients", profile.AllowedClients); err != nil {
			return err
		}
		if err := validateACPNameList(name, "allowed_agents", profile.AllowedAgents); err != nil {
			return err
		}
		seenMethods := make(map[string]struct{}, len(profile.DeniedMethods))
		if len(profile.DeniedMethods) > maxACPDeniedMethods {
			return fmt.Errorf("profiles[%q].denied_methods exceeds %d entries", name, maxACPDeniedMethods)
		}
		for _, method := range profile.DeniedMethods {
			if method == "" || len(method) > 256 || strings.TrimSpace(method) != method || strings.ContainsAny(method, "\r\n\x00") {
				return fmt.Errorf("profiles[%q].denied_methods contains invalid method %q", name, method)
			}
			if _, duplicate := seenMethods[method]; duplicate {
				return fmt.Errorf("profiles[%q].denied_methods contains duplicate %q", name, method)
			}
			seenMethods[method] = struct{}{}
		}
	}
	return nil
}

func validateACPMode(mode string, allowEmpty bool) error {
	switch strings.TrimSpace(mode) {
	case "observe", "action":
		return nil
	case "":
		if allowEmpty {
			return nil
		}
	}
	return fmt.Errorf("invalid value %q (want observe or action)", mode)
}

func validateACPStableName(field, value string) error {
	if !acpStableNamePattern.MatchString(value) {
		return fmt.Errorf("%s %q must match %s", field, value, acpStableNamePattern.String())
	}
	return nil
}

// validateACPBindings checks the client and agent pins.
//
// profileRequired is false once per-pair bindings exist: a pin then records
// only that its half is enabled and the pair supplies the profile, so
// demanding one here would reject every configuration the CLI writes.
// Resolution still falls back to default_profile, which is itself required
// whenever ACP is enabled, so an unset pin can never leave a pair without a
// profile to resolve.
func validateACPBindings(
	kind string,
	bindings map[string]ACPBinding,
	profiles map[string]ACPProfile,
	profileRequired bool,
) error {
	for _, name := range sortedACPKeys(bindings) {
		if err := validateACPStableName(kind, name); err != nil {
			return err
		}
		binding := bindings[name]
		if binding.Profile == "" {
			if profileRequired {
				return fmt.Errorf("%s[%q].profile is required", kind, name)
			}
			continue
		}
		if err := validateACPStableName(kind+" profile", binding.Profile); err != nil {
			return err
		}
		if _, ok := profiles[binding.Profile]; !ok {
			return fmt.Errorf("%s[%q].profile %q is not defined in profiles", kind, name, binding.Profile)
		}
	}
	return nil
}

// validateACPPairBindings checks the per-pair bindings, whose keys are
// "<client>/<agent>" rather than a single stable name, and whose halves must
// both be configured. A pair naming a client or agent that is not present
// would otherwise sit in the file looking effective while evaluation refuses
// it for an unrelated-looking reason.
func validateACPPairBindings(a ACPConfig) error {
	for _, name := range sortedACPKeys(a.Bindings) {
		client, agent, ok := strings.Cut(name, "/")
		if !ok {
			return fmt.Errorf("bindings[%q] must be \"<client>/<agent>\"", name)
		}
		if err := validateACPStableName("bindings client", client); err != nil {
			return err
		}
		if err := validateACPStableName("bindings agent", agent); err != nil {
			return err
		}
		if _, ok := a.Clients[client]; !ok {
			return fmt.Errorf("bindings[%q] client %q is not defined in clients", name, client)
		}
		if _, ok := a.Agents[agent]; !ok {
			return fmt.Errorf("bindings[%q] agent %q is not defined in agents", name, agent)
		}
		binding := a.Bindings[name]
		if binding.Profile == "" {
			continue
		}
		if err := validateACPStableName("bindings profile", binding.Profile); err != nil {
			return err
		}
		if _, ok := a.Profiles[binding.Profile]; !ok {
			return fmt.Errorf("bindings[%q].profile %q is not defined in profiles", name, binding.Profile)
		}
	}
	return nil
}

func validateACPNameList(profile, field string, values []string) error {
	if len(values) > maxACPBindings {
		return fmt.Errorf("profiles[%q].%s exceeds %d entries", profile, field, maxACPBindings)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validateACPStableName("profiles[\""+profile+"\"]."+field, value); err != nil {
			return err
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("profiles[%q].%s contains duplicate %q", profile, field, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func sortedACPKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
