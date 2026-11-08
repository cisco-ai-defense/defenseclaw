// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// MCPLaunchDigest is a hex SHA-256 over everything that decides what an MCP
// server starts or reaches: URL, command, arguments, environment, working
// folder, transport, headers and authentication. It leaves out where the
// definition was read from and the name it is listed under, so the hook that
// read a definition as the user and the gateway that holds the published
// record of the same definition compute the same value. A hook fact cannot
// carry every argument, a long URL or the environment, so the digest is what
// binds a claim to the complete definition that was scanned (GAP-0686).
// It is empty when the entry cannot be encoded.
func MCPLaunchDigest(entry MCPServerEntry) string {
	entry.Name, entry.Source, entry.SourceScope = "", "", ""
	entry.TrustRequired, entry.Bundled = false, false
	raw, err := json.Marshal(entry)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
