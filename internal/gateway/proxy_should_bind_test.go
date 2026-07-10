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
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestProxyShouldBindForConnector_MatchesProxyClassification is the
// regression net for the multi-connector boot guard. proxyShouldBindForConnector
// MUST agree with connector.IsProxyConnector for every registered connector:
// proxy connectors (openclaw/zeptoclaw) bind a port and cannot share a
// multi-connector process; every hook connector must return false so it can.
//
// opencode regressed here: it was a hook-only connector missing from the
// allowlist, so it fell to the `default: return true` arm and the gateway
// rejected any multi-connector set containing opencode with "requires a proxy
// binding". This test iterates the real default registry so a future hook
// connector cannot reintroduce that gap.
func TestProxyShouldBindForConnector_MatchesProxyClassification(t *testing.T) {
	reg := connector.NewDefaultRegistry()
	gc := &config.GuardrailConfig{}
	for _, name := range reg.Names() {
		conn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("registry.Get(%q) returned !ok", name)
		}
		got := proxyShouldBindForConnector(conn, gc)
		want := connector.IsProxyConnector(name)
		if got != want {
			t.Errorf("proxyShouldBindForConnector(%q)=%v, want %v (IsProxyConnector). "+
				"Hook connectors must return false so they can share a multi-connector process.",
				name, got, want)
		}
	}
}
