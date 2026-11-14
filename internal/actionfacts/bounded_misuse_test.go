// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// A misused bounded.Counter in this package panics under go test
// (bounded.TestAdopters).
func init() { bounded.PanicOnMisuse(true) }
