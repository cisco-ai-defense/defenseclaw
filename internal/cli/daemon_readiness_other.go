// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "time"

// platformStartReadinessTimeout bounds how long start and restart wait for a
// launched gateway to report READY before stopping it.
const platformStartReadinessTimeout = 60 * time.Second

// startReadinessProgressFactor: see daemon_readiness_windows.go. Each setup
// step (and each retry of a slow agent probe) gives start and restart another
// 60 s, up to 180 s in all: a Codex probe that timed out three times (20 s
// each) used up the whole 60 s, so restart stopped the gateway and every
// connector lost enforcement instead of one being shown NOT RUNNING
// (GAP-1850). A start that makes no progress still fails at 60 s.
const startReadinessProgressFactor = 3

// startupRetriesSQLiteIO: see daemon_readiness_windows.go. Elsewhere an
// event-history I/O error stays an immediate startup failure.
var startupRetriesSQLiteIO = false
