//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// windowsSIDPersonAccount: SIDs exist only on Windows. Replaceable in tests.
var windowsSIDPersonAccount = func(string) (person, known bool) { return false, false }
