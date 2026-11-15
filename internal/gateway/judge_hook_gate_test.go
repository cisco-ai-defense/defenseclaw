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
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// An enabled judge with an empty hook gate judges proxy traffic only; the
// gateway names the hook connectors the rules decide alone.
func TestHookConnectorsOutsideJudge(t *testing.T) {
	roster := func() map[string]config.PerConnectorGuardrailConfig {
		return map[string]config.PerConnectorGuardrailConfig{"codex": {}, "claudecode": {}, "openclaw": {}}
	}
	cases := []struct {
		name    string
		enabled bool
		gate    []string
		want    []string
	}{
		{name: "judge off", enabled: false, gate: nil, want: nil},
		{name: "empty gate", enabled: true, gate: nil, want: []string{"claudecode", "codex"}},
		{name: "explicit empty gate", enabled: true, gate: []string{}, want: []string{"claudecode", "codex"}},
		{name: "every connector", enabled: true, gate: []string{"*"}, want: nil},
		{name: "one connector", enabled: true, gate: []string{"claude-code"}, want: []string{"codex"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Connectors = roster()
			cfg.Guardrail.Judge.Enabled = tc.enabled
			cfg.Guardrail.Judge.HookConnectors = tc.gate
			if got := hookConnectorsOutsideJudge(cfg); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("hookConnectorsOutsideJudge = %v, want %v", got, tc.want)
			}
		})
	}
	if got := hookConnectorsOutsideJudge(nil); got != nil {
		t.Fatalf("nil config = %v, want nil", got)
	}
}
