//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

// RootOwnedAgentConfigPaths has no meaning on Windows, which has no root-run
// gateway that leaves root-owned files in the account home.
func RootOwnedAgentConfigPaths(string) []string { return nil }
