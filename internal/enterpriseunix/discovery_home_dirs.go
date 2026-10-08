// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"gopkg.in/yaml.v3"
)

// codeDiscoveryHomeDirNotEnrolled names an ai_discovery.home_dirs entry
// that is not the home of an enrolled account. It is a warning: verify does
// not fail on it.
const codeDiscoveryHomeDirNotEnrolled = "ai_discovery_home_dir_not_enrolled"

// describeDiscoveryHomeDirs warns about each ai_discovery.home_dirs entry
// that is not an enrolled account's home on Linux. AI Discovery scans every
// enrolled account's home as that account and reads its connector email
// there; the gateway's sandbox cannot read a home, so an entry for any other
// folder is never scanned. An administrator who listed the homes to enable
// connector email got no address and no word why (GAP-0961). macOS writes
// its own home_dirs at install, so it is not checked there.
func (l *lifecycle) describeDiscoveryHomeDirs() {
	env := l.env
	if env.GOOS != "linux" {
		return
	}
	raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		return
	}
	var doc struct {
		AIDiscovery struct {
			HomeDirs []string `yaml:"home_dirs"`
		} `yaml:"ai_discovery"`
	}
	if yaml.Unmarshal(raw, &doc) != nil || len(doc.AIDiscovery.HomeDirs) == 0 {
		return
	}
	manifest, err := enterprisehooks.LoadStandaloneManifest(env.P(env.Layout.ManifestPath))
	if err != nil {
		return
	}
	enrolled := map[string]bool{}
	for _, target := range manifest.Targets {
		if home := strings.TrimSpace(target.UserHome); home != "" && (target.Enabled == nil || *target.Enabled) {
			enrolled[filepath.Clean(home)] = true
		}
	}
	for _, home := range doc.AIDiscovery.HomeDirs {
		home = strings.TrimSpace(home)
		if home == "" || enrolled[filepath.Clean(home)] {
			continue
		}
		l.result.AddWarning(codeDiscoveryHomeDirNotEnrolled, fmt.Sprintf(
			"ai_discovery.home_dirs names %s, which is not the home of an enrolled account; AI Discovery scans every enrolled "+
				"account's home (and reads its connector email there) without home_dirs, and never scans this folder: remove "+
				"the entry, or enroll its account", home))
	}
}
