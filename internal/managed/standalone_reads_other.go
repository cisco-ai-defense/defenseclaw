//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

// principalReadsPath is false off Windows: there is no Windows access list to
// read, so the fix only ever removes the account's entries.
func principalReadsPath(string, string) bool { return false }
