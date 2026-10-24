// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

// perUserInstalledModeComment is what a per-user shell hook renders after its
// baked FAIL_MODE, and perUserEnvFailModeRead is any read of the variable: no
// hook outside Secure Client delivery reads a fail mode from its environment
// (GAP-0315, 1.0.4 lead directive).
const (
	perUserInstalledModeComment = "# The installed mode is the fail mode: DEFENSECLAW_FAIL_MODE in the agent's"
	perUserEnvFailModeRead      = "${DEFENSECLAW_FAIL_MODE"
)
