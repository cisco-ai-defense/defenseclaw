// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package opencodebridge owns the dependency-free OpenCode v2 adapter shared
// by the per-user, sandbox and machine-policy bridge artifacts.
package opencodebridge

import _ "embed"

// Adapter is appended to each bridge before publication. It deliberately
// imports no npm package: OpenCode accepts the plain plugin definition.
//
//go:embed adapter.js
var Adapter string
