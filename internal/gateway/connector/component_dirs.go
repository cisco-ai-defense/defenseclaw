// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"strings"
)

// ComponentDirsForHome lists the skill and plugin folders conn scans for the
// account whose profile is home: conn's ComponentTargets for the calling
// process's own profile ownHome, moved to the same place below home. A
// folder outside ownHome is not a user's and is left out. A managed Windows
// gateway watches these folders for every enrolled user, and the hook
// enumerator grants the gateway service read access to exactly these
// folders, so both use this one list (GAP-0913).
func ComponentDirsForHome(conn Connector, ownHome, home string) (skills, plugins []string) {
	scanner, ok := conn.(ComponentScanner)
	if !ok || !scanner.SupportsComponentScanning() {
		return nil, nil
	}
	components := scanner.ComponentTargets("")
	rebase := func(dirs []string) []string {
		var out []string
		for _, dir := range dirs {
			if userDir, ok := RebaseUnderHome(dir, ownHome, home); ok {
				out = append(out, userDir)
			}
		}
		return out
	}
	return rebase(components["skill"]), rebase(components["plugin"])
}

// RebaseUnderHome moves path from below fromHome to the same place below
// toHome. Paths outside fromHome, and fromHome itself, are refused.
func RebaseUnderHome(path, fromHome, toHome string) (string, bool) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(fromHome) {
		return "", false
	}
	rel, err := filepath.Rel(filepath.Clean(fromHome), filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.Join(toHome, rel), true
}
