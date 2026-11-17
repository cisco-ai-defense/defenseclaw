// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !windows

package connector

// isWindowsConnectionRefused is false off Windows; the shared refusal check
// (hook_free_api_addr_test.go) also accepts WSAECONNREFUSED there.
func isWindowsConnectionRefused(error) bool { return false }
