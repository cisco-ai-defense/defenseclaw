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
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// windowsEnterpriseManifestUncoveredRows lists the rows of an administrator-supplied
// Windows guardian manifest that the installed manifest does not carry with the same
// enrollment state. Rows the installed manifest has beyond the supplied ones
// are not drift: the standalone hook enumerator adds rows for users it
// discovers, and treating those as drift would make every ensure reapply the
// supplied manifest.
func windowsEnterpriseManifestUncoveredRows(required, installed []enterprisehooks.ManifestTarget) []string {
	byKey := make(map[string]enterprisehooks.ManifestTarget, len(installed))
	for _, target := range installed {
		byKey[windowsEnterpriseManifestRowKey(target)] = target
	}
	var uncovered []string
	for _, want := range required {
		key := windowsEnterpriseManifestRowKey(want)
		got, ok := byKey[key]
		if !ok || !windowsEnterpriseManifestRowsEqual(want, got) {
			uncovered = append(uncovered, strings.TrimSpace(want.SID)+"/"+strings.ToLower(strings.TrimSpace(want.Connector)))
		}
	}
	sort.Strings(uncovered)
	return uncovered
}

func windowsEnterpriseManifestRowKey(target enterprisehooks.ManifestTarget) string {
	identity := strings.ToUpper(strings.TrimSpace(target.SID))
	if identity == "" {
		identity = strings.TrimSpace(target.User)
	}
	return identity + "\x00" + strings.ToLower(strings.TrimSpace(target.Connector))
}

func windowsEnterpriseManifestRowsEqual(want, got enterprisehooks.ManifestTarget) bool {
	enabled := func(target enterprisehooks.ManifestTarget) bool {
		return target.Enabled == nil || *target.Enabled
	}
	// Windows paths: case-insensitive, either separator, no trailing
	// separator. Kept platform-neutral so it is testable everywhere.
	samePath := func(left, right string) bool {
		normalize := func(value string) string {
			return strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(value), "/", `\`), `\`)
		}
		return strings.EqualFold(normalize(left), normalize(right))
	}
	return enabled(want) == enabled(got) &&
		want.Deferred == got.Deferred &&
		strings.TrimSpace(want.AgentVersion) == strings.TrimSpace(got.AgentVersion) &&
		samePath(want.UserHome, got.UserHome) &&
		samePath(want.DataDir, got.DataDir)
}
