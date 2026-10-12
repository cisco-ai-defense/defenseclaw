// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package launchdstandalone

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
)

// The sandbox LaunchAgents live in agents/, outside the *.plist glob of
// assets.go: they are per-user agents in /Library/LaunchAgents, not the
// LaunchDaemons Labels lists and the lifecycle bootstraps for the deployment.
//
//go:embed agents/*.plist
var agentFiles embed.FS

// AgentLabels lists the sandbox LaunchAgent labels in a stable order.
func AgentLabels() []string {
	entries, _ := fs.ReadDir(agentFiles, "agents")
	labels := make([]string, 0, len(entries))
	for _, entry := range entries {
		labels = append(labels, strings.TrimSuffix(entry.Name(), ".plist"))
	}
	sort.Strings(labels)
	return labels
}

// ReadAgentPlist returns the embedded plist of the sandbox LaunchAgent label.
func ReadAgentPlist(label string) ([]byte, error) {
	return agentFiles.ReadFile("agents/" + label + ".plist")
}
