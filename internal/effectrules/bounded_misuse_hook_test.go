// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effectrules

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// This package registers its caps with bounded (caps_registry.go); its tests
// run with the misuse checks on, as every adopter of bounded does
// (bounded.TestAdopters).
func init() { bounded.PanicOnMisuse(true) }
