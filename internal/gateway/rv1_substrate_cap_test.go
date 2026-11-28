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

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// RV1 P4-1: the workspace cap is clamped to 1 MiB-64 GiB (design 2.6).
func TestSubstrateWorkspaceMaxClamp(t *testing.T) {
	for _, c := range []struct{ in, want int64 }{
		{0, config.DefaultSubstrateWorkspaceMaxBytes},
		{-1, config.DefaultSubstrateWorkspaceMaxBytes},
		{512, 1 << 20},
		{1<<20 - 1, 1 << 20},
		{1 << 20, 1 << 20},
		{5 << 30, 5 << 30},
		{relay.MaxFilesBytes + 1, relay.MaxFilesBytes},
	} {
		if got := substrateWorkspaceMax(c.in); got != c.want {
			t.Errorf("substrateWorkspaceMax(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
