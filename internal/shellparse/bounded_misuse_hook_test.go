// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// A package that imports the bound rule runs its tests with the misuse of an
// unbound counter a panic, not a silent unread (TestAdopters of
// internal/guardrail/bounded).
func init() { bounded.PanicOnMisuse(true) }
