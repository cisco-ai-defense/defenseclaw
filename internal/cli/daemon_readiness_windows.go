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
// A gateway that exits is still reported at once.
const platformStartReadinessTimeout = 240 * time.Second

// startReadinessProgressFactor bounds how far connector setup progress may
// extend that timeout: up to 12 minutes while a setup step finishes within
// every 240 s window. A loaded dc-win2 needed 2 minutes for one connector
// and over 4 for four (GAP-1556).
const startReadinessProgressFactor = 3

// startupRetriesSQLiteIO lets readiness wait out an event-history SQLite I/O
// error as it does BUSY/LOCKED contention. On Windows an antivirus scan of a
// large audit.db (just copied for the upgrade rollback) can hold the file past
// SQLite's own sharing-violation retries, which surfaces as SQLITE_IOERR; the
// writer clears it after its next commit. An upgrade with a 1.3 GB audit.db
// rolled back that way, and the restored gateway failed the same way, while a
// start a minute later worked (GAP-1519).
var startupRetriesSQLiteIO = true
