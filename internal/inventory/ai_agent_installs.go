// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
)

// agentInstalls lists, on a managed scan, every copy of the agent binary bin
// in the bin folders of each scanned home and the machine prefixes, so an
// agent installed in several places is reported once per install. The
// generic name "agent" proves nothing on its own and is not searched.
func (s *ContinuousDiscoveryService) agentInstalls(bin string) []string {
	if !s.opts.ManagedEnterprise || s.sandbox != nil || bin == "agent" || bin != filepath.Base(bin) {
		return nil
	}
	var out []string
	for _, home := range s.homesToScan() {
		for _, dir := range agentBinaryDirs(home) {
			path := filepath.Join(dir, bin)
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
				out = append(out, path)
			}
		}
	}
	return out
}

// installLocation is where an install is, on a managed scan: "~/rel" under
// a scanned home, so no account name is sent, else the absolute path of a
// system location. A path in the folder that holds the homes is another
// account's (or one not scanned), and sends nothing, like one that cannot
// be sent.
func (s *ContinuousDiscoveryService) installLocation(path string) string {
	if !s.opts.ManagedEnterprise {
		return ""
	}
	if location, inHome := s.skillLocation(path); inHome {
		return location
	}
	if !filepath.IsAbs(path) || len(path) > maxSkillLocation || containsUnicodeControl(path) {
		return ""
	}
	for _, home := range s.homesToScan() {
		// The folder of /root is the file system root, which holds no homes.
		if parent := filepath.Dir(home); parent != filepath.Dir(parent) && pathBelow(parent, path) {
			return ""
		}
	}
	if systemAgentInstallLocation(path) {
		return filepath.Clean(path)
	}
	return ""
}
