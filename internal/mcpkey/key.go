// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Package mcpkey encodes a configured MCP server's durable scope as one tuple.
package mcpkey

import (
	"encoding/hex"
	"strconv"
	"strings"
)

const prefix = "mcp:v2:"

// Identity is the scope stored with a server's admission result.
type Identity struct {
	Name      string `json:"name"`
	Connector string `json:"connector"`
	Home      string `json:"home"`
	Project   string `json:"project"`
}

// Encode makes a distinct key for every tuple, including fields containing
// punctuation used in earlier keys.
func Encode(identity Identity) string {
	var key strings.Builder
	key.WriteString(prefix)
	for _, field := range []string{identity.Name, identity.Connector, identity.Home, identity.Project} {
		key.WriteString(strconv.Itoa(len(field)))
		key.WriteByte(':')
		key.WriteString(hex.EncodeToString([]byte(field)))
	}
	return key.String()
}

// Decode accepts only one complete, canonical versioned tuple key.
func Decode(path string) (Identity, bool) {
	var identity Identity
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return identity, false
	}
	fields := []*string{&identity.Name, &identity.Connector, &identity.Home, &identity.Project}
	for _, field := range fields {
		colon := strings.IndexByte(rest, ':')
		if colon < 1 {
			return Identity{}, false
		}
		n, err := strconv.Atoi(rest[:colon])
		if err != nil || n < 0 || strconv.Itoa(n) != rest[:colon] || n > (len(rest)-colon-1)/2 {
			return Identity{}, false
		}
		raw, err := hex.DecodeString(rest[colon+1 : colon+1+2*n])
		if err != nil {
			return Identity{}, false
		}
		*field = string(raw)
		rest = rest[colon+1+2*n:]
	}
	return identity, rest == ""
}
