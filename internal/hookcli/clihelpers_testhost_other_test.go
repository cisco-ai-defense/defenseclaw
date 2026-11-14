// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookcli

import "testing"

// skipIfLocalSystem is a no-op off Windows.
func skipIfLocalSystem(*testing.T, string) {}
