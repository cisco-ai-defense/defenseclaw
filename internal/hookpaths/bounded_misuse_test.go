// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// A misused Counter in this package fails its test instead of counting
// silently (the one bound rule; bounded.TestAdopters enforces this file).
func init() { bounded.PanicOnMisuse(true) }
