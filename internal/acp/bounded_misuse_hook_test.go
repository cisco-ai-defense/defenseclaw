// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// A misused bound Counter panics where it is made in this package's tests
// (bounded.TestAdopters checks every package that imports bounded).
func init() { bounded.PanicOnMisuse(true) }
