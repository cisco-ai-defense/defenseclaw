// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// The script reading reports the bounds it hits as a bounded.CapSet
// (HostScriptReadings). The bound rule's adopter check wants every package
// that imports it to run its tests with a misuse panicking, not on the
// production fallback.
func init() { bounded.PanicOnMisuse(true) }
