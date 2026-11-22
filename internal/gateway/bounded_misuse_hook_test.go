// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// The gateway's tests run with the bound helper's misuse checks on: a
// Counter that was never bound, or one bound to another Truncated, panics
// where the mistake is made (bounded.PanicOnMisuse).
func init() { bounded.PanicOnMisuse(true) }
