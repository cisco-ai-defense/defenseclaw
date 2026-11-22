// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookcli

import (
	// The hook reads config.yaml with the checks the gateway reads it with,
	// so it decides what the full-CLI hook decided (rel-1-0-10:GAP-0603):
	//   - the verdict of the rule loader on a guardrail.custom_packs entry
	//     (config.RegisterCustomRulePackValidator, guardrail init): a pinned
	//     custom pack sets the outage tier of the call from its manifest
	//     posture only when the loader accepts it and its files hash to the
	//     pin; without the loader every pinned selection was strict;
	//   - the sandbox profile pack check (config.SandboxProfilePackCheck,
	//     openshell/packs init): a profile floor the gateway refuses is a
	//     config load error here too, which closes the outage.
	// Both register in their package init, as in the gateway binary.
	_ "github.com/defenseclaw/defenseclaw/internal/guardrail"
	_ "github.com/defenseclaw/defenseclaw/internal/openshell/packs"
)
