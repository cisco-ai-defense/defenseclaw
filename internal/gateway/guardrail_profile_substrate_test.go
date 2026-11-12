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
)

// A match.substrate selector names Agent Substrate actors only: a host
// subject has no atespace, so neither a substrate-only match nor one that
// ANDs host keys with substrate keys may select it.
func TestSubstrateMatchNeverSelectsAHostSubject(t *testing.T) {
	subject := profileSubject{}
	sub := &config.ProfileMatchSubstrate{Atespaces: []string{"eng-web"}}
	for name, m := range map[string]config.ProfileMatch{
		"substrate only":      {Substrate: sub},
		"connector+substrate": {Connectors: []string{"codex"}, Substrate: sub},
	} {
		if _, _, ok := assignmentMatches(m, &subject, &subjectGroups{}, true, "codex", ""); ok {
			t.Errorf("%s selected a host subject", name)
		}
	}
	if _, _, ok := assignmentMatches(config.ProfileMatch{Connectors: []string{"codex"}}, &subject, &subjectGroups{}, true, "codex", ""); !ok {
		t.Fatal("control: a connector match no longer selects")
	}
}
