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

//go:build windows

package cli

import "time"

// platformStartReadinessTimeout bounds how long start and restart wait for a
// launched gateway to report READY before stopping it. A per-user Windows
// gateway cold start on a busy host (Defender scanning the executable and the
// per-user databases) was measured at 135 s before the banner and 142 s before
// the API listened, so the 60 s used elsewhere stopped a gateway that was
// still making progress and connector setup then failed (GAP-1206, GAP-1396).
// A gateway that exits is still reported at once. With Defender at 50-100 %
// CPU, 240 s was still too short: a start was stopped with only two of eight
// connectors admitted, and the next start needed 312 s (GAP-1206).
const platformStartReadinessTimeout = 600 * time.Second

// startupRetriesSQLiteIO lets readiness wait out an event-history SQLite I/O
// error as it does BUSY/LOCKED contention. On Windows an antivirus scan of a
// large audit.db (just copied for the upgrade rollback) can hold the file past
// SQLite's own sharing-violation retries, which surfaces as SQLITE_IOERR; the
// writer clears it after its next commit. An upgrade with a 1.3 GB audit.db
// rolled back that way, and the restored gateway failed the same way, while a
// start a minute later worked (GAP-1519).
var startupRetriesSQLiteIO = true
