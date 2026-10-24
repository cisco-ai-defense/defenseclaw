// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "testing"

// isolateTestHost is a no-op off Windows (see testhost_windows_test.go).
func isolateTestHost() func() { return func() {} }

// skipIfLocalSystem is a no-op off Windows.
func skipIfLocalSystem(*testing.T, string) {}
