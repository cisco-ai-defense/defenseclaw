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

package cli

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0601: the leader runs its chain state with the start grace that
// covers a gateway's note of a step it could not record during an outage.
func TestLeaderChainStartGraceGAP0601(t *testing.T) {
	opts, _ := leaderChainOptions(&config.Config{}, nil, t.TempDir(), time.Hour)
	if opts.StartGrace != leaderChainStartGrace || leaderChainStartGrace < 7*time.Second {
		t.Fatalf("leader chain start grace %s (const %s), want at least one note retry (5 s) plus its timeout (2 s)",
			opts.StartGrace, leaderChainStartGrace)
	}
}
