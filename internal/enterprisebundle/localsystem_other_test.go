// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisebundle

// testRunsAsLocalSystem is false off Windows.
func testRunsAsLocalSystem() bool { return false }
