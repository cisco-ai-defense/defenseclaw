// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// The tests of a package that imports the bound helper run with the misuse
// panic on (internal/guardrail/bounded TestAdopters).
func init() { bounded.PanicOnMisuse(true) }
