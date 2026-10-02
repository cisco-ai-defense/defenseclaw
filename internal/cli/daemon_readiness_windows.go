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
