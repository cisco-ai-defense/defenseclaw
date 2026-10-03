// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

// The runtime pipeline canary ("setup <destination> test" and doctor's
// delivery check) is a generated agent root plus one model child. Its model
// child names a DefenseClaw diagnostic model, not a real vendor model, so a
// destination's model-usage, cost and latency views never count a doctor run
// as a call the user made to that vendor (GAP-2534).
const (
	RuntimeCanaryAgentSpanName = "invoke_agent diagnostic"
	RuntimeCanaryProvider      = "defenseclaw"
	RuntimeCanaryModel         = "defenseclaw-diagnostic"
	RuntimeCanaryModelSpanName = "chat " + RuntimeCanaryModel
)
