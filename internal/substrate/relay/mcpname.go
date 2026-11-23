// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package relay

import "regexp"

// MCPNameRE is the name of a bridged MCP server: the NAME of `--mcp
// NAME=CMD`, the last segment of the mcp/NAME route and the dc.scope of its
// stream (mcp:NAME). The launcher, the gateway and the relay all use this
// one pattern.
var MCPNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
