// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "testing"

// isolateTestHost is a no-op off Windows (see testhost_windows_test.go).
func isolateTestHost() func() { return func() {} }

// guardTestMachine is a no-op off Windows.
func guardTestMachine() func() error { return func() error { return nil } }

// guardTestSandbox is a no-op off Windows.
func guardTestSandbox() func() error { return func() error { return nil } }

// testProcessPriority is not tracked off Windows.
func testProcessPriority() string { return "" }

// requireAdministratorTestToken is a no-op off Windows.
func requireAdministratorTestToken(*testing.T, string) {}

// skipIfLocalSystem is a no-op off Windows.
func skipIfLocalSystem(*testing.T, string) {}
