// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package testenv

import "testing"

// RequireElevated is a no-op off Windows: the administrator-token fixtures it
// guards are Windows access-control objects (see elevated_windows.go).
func RequireElevated(testing.TB, string) {}
