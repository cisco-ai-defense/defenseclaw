// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package launchdstandalone embeds the standalone managed-enterprise
// LaunchDaemons. The Secure Client daemons in packaging/launchd are a
// separate, unchanged production artifact.
package launchdstandalone

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.plist
var files embed.FS

// Labels lists the daemon labels in a stable order.
func Labels() []string {
	entries, _ := fs.ReadDir(files, ".")
	labels := make([]string, 0, len(entries))
	for _, entry := range entries {
		labels = append(labels, strings.TrimSuffix(entry.Name(), ".plist"))
	}
	sort.Strings(labels)
	return labels
}

// ReadPlist returns the embedded plist for label.
func ReadPlist(label string) ([]byte, error) {
	return files.ReadFile(label + ".plist")
}
