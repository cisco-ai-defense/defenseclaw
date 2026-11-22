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
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// TestSubstrateSecretViewS6a: list's expiry column and 7-day warning, and
// test --agent's words for an agent whose policy carries the secret, does
// not, or could not be read.
func TestSubstrateSecretViewS6a(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	for _, c := range []struct {
		exp  *time.Time
		want string
	}{{nil, "-"}, {at(-time.Minute), "expired"}, {at(5 * time.Hour), "in 5 h"}, {at(72 * time.Hour), "in 3 d"}} {
		if got := substrateUntil(c.exp, now); got != c.want {
			t.Errorf("until %v = %q, want %q", c.exp, got, c.want)
		}
	}
	if d, ok := substrateExpiresSoon(api.Secret{Expires: at(50 * time.Hour)}, now); !ok || d != 3 {
		t.Errorf("soon: %d %v", d, ok)
	}
	for _, s := range []api.Secret{{Expires: at(8 * 24 * time.Hour)}, {Expires: at(-time.Hour)}, {Expires: at(time.Hour), Reason: "secret_expired"}, {}} {
		if _, ok := substrateExpiresSoon(s, now); ok {
			t.Errorf("no warning expected for %+v", s)
		}
	}
	if k := substrateSecretKind(api.Secret{Kind: "template", Template: "gitlab"}); k != "template gitlab" {
		t.Errorf("kind %q", k)
	}

	yes, no := true, false
	base := api.Secret{Name: "gl-work", Hosts: []string{"gitlab.com"}, Kind: "template", Template: "gitlab", Status: "set", Expires: at(72 * time.Hour)}
	for name, c := range map[string]struct {
		agent *api.SecretTestAgent
		want  []string
	}{
		"carried":     {&api.SecretTestAgent{Actor: "eng-web/alice-1", InPolicy: &yes}, []string{"Bound to gitlab.com (template gitlab), expires in 3 d.", "Agent eng-web/alice-1: its policy carries the secret."}},
		"not carried": {&api.SecretTestAgent{Actor: "eng-web/alice-1", InPolicy: &no, Reason: "secret_not_in_policy"}, []string{"its policy does not carry the secret. The agent's network policy"}},
		"unknown":     {&api.SecretTestAgent{Actor: "eng-web/alice-1"}, []string{"could not read its policy just now"}},
	} {
		var b bytes.Buffer
		printSubstrateSecretTest(&b, api.SecretTest{Secret: base, Agent: c.agent}, now)
		for _, w := range c.want {
			if !strings.Contains(b.String(), w) {
				t.Errorf("%s: %q missing in:\n%s", name, w, b.String())
			}
		}
	}
}
