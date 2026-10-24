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

import "sort"

// IsRetiredConnector reports whether name (any spelling the loader accepts)
// is a connector 1.0.4 removed. until 1.1: the loader drops its settings, and
// the staged upgrade check must expect that (GAP-0290).
func IsRetiredConnector(name string) bool {
	switch normalizeConnectorKey(name) {
	case "openhands", "omnigent":
		return true
	}
	return false
}

func dropRetiredKeys[T any](entries map[string]T) bool {
	changed := false
	for name := range entries {
		if IsRetiredConnector(name) {
			delete(entries, name)
			changed = true
		}
	}
	return changed
}

func dropRetiredNames(names []string) ([]string, bool) {
	if len(names) == 0 {
		return names, false
	}
	var kept []string
	for _, name := range names {
		if IsRetiredConnector(name) {
			continue
		}
		kept = append(kept, name)
	}
	return kept, len(kept) != len(names)
}

func isOnlyRetiredNames(names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, name := range names {
		if !IsRetiredConnector(name) {
			return false
		}
	}
	return true
}

// until 1.1: older 0.8.x and 1.0.x configs can still name these removed
// connectors. Drop their settings at load so the remaining roster can start.
func dropRetiredConnectorSettings(cfg *Config) {
	if cfg == nil {
		return
	}
	changed := dropRetiredKeys(cfg.Guardrail.Connectors)
	changed = dropRetiredKeys(cfg.AssetPolicy.Connectors) || changed
	changed = dropRetiredKeys(cfg.ApplicationProtection.Connectors) || changed
	changed = dropRetiredKeys(cfg.Observability.Connectors) || changed
	changed = dropRetiredKeys(cfg.ConnectorHooks) || changed
	changed = dropRetiredKeys(cfg.Enterprise.MachinePolicy.Connectors) || changed
	for name, profile := range cfg.Guardrail.Profiles {
		if dropRetiredKeys(profile.Connectors) {
			changed = true
		}
		if profile.Sandbox != nil {
			var dropped bool
			profile.Sandbox.RequiredFor, dropped = dropRetiredNames(profile.Sandbox.RequiredFor)
			changed = dropped || changed
			hadAllowedHarnesses := len(profile.Sandbox.AllowedHarnesses) > 0
			profile.Sandbox.AllowedHarnesses, dropped = dropRetiredNames(profile.Sandbox.AllowedHarnesses)
			changed = dropped || changed
			if hadAllowedHarnesses && len(profile.Sandbox.AllowedHarnesses) == 0 {
				// until 1.1: empty means unrestricted, so refuse this profile's sandbox.
				allowed := false
				profile.Sandbox.Allowed = &allowed
			}
		}
		cfg.Guardrail.Profiles[name] = profile
	}
	assignments := cfg.Guardrail.ProfileAssignments[:0]
	for _, assignment := range cfg.Guardrail.ProfileAssignments {
		var dropped bool
		assignment.Match.Connectors, dropped = dropRetiredNames(assignment.Match.Connectors)
		changed = dropped || changed
		// until 1.1: an assignment that named only removed connectors applied
		// to none that remain; an empty connector list would match them all.
		if dropped && len(assignment.Match.Connectors) == 0 {
			continue
		}
		assignments = append(assignments, assignment)
	}
	cfg.Guardrail.ProfileAssignments = assignments
	apOnlyRetired := isOnlyRetiredNames(cfg.ApplicationProtection.IncludeConnectors)
	harnessOnlyRetired := isOnlyRetiredNames(cfg.OpenShell.Harnesses)
	adminOnlyRetired := isOnlyRetiredNames(cfg.OpenShell.Admin.AllowedHarnesses)
	for _, names := range []*[]string{&cfg.Guardrail.Judge.HookConnectors, &cfg.ApplicationProtection.IncludeConnectors,
		&cfg.ApplicationProtection.ExcludeConnectors, &cfg.OpenShell.Harnesses,
		&cfg.OpenShell.Admin.RequiredFor, &cfg.OpenShell.Admin.AllowedHarnesses} {
		var dropped bool
		*names, dropped = dropRetiredNames(*names)
		changed = dropped || changed
	}
	// until 1.1: an emptied allow-list must not turn into an unrestricted one.
	if apOnlyRetired {
		cfg.ApplicationProtection.Enabled = false
	}
	if harnessOnlyRetired {
		cfg.OpenShell.Enabled = false
	}
	if adminOnlyRetired {
		allowed := false
		cfg.OpenShell.Admin.Allowed = &allowed
	}
	if IsRetiredConnector(cfg.Guardrail.Connector) {
		cfg.Guardrail.Connector = ""
		changed = true
	}
	if IsRetiredConnector(string(cfg.Claw.Mode)) {
		cfg.Claw.Mode = ""
		changed = true
	}
	if cfg.Guardrail.Connector == "" && len(cfg.Guardrail.Connectors) > 0 {
		remaining := make([]string, 0, len(cfg.Guardrail.Connectors))
		for name := range cfg.Guardrail.Connectors {
			remaining = append(remaining, name)
		}
		sort.Strings(remaining)
		cfg.Guardrail.Connector = remaining[0]
	}
	if changed {
		cfg.LegacyConnectorNotices = append(cfg.LegacyConnectorNotices,
			"OpenHands and OmniGent connectors were removed; their configuration was dropped until 1.1; run defenseclaw migrate to update config.yaml")
	}
}
