// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "os"

// replaceLikeDiscovery renames source over destination as Python discovery
// replaces agent_discovery.json (file_permissions.replace_file_durable).
func replaceLikeDiscovery(source, destination string) error {
	return os.Rename(source, destination)
}
