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

//go:build linux

package kit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// GAP-0187: Codex on a Bedrock install reaches Luna through Bedrock
// Runtime's OpenAI-compatible Responses API on /llm/bedrock; with an OpenAI
// route it stays on /llm/openai. Both carry only the placeholder key.
func TestCodexModelRoutes(t *testing.T) {
	for _, c := range []struct{ provider, base, model string }{
		{"bedrock", "/llm/bedrock/openai/v1", `model = "` + LunaModel + `"`},
		{"openai", "/llm/openai/v1", ""},
	} {
		mc := string(file(overlayFor(t, harness.Codex, c.provider), connector.CodexSandboxManagedConfigPath))
		if !strings.Contains(mc, "base_url = '"+DefaultGatewayURL+c.base+"'") || !strings.Contains(mc, "env_key = 'OPENAI_API_KEY'") {
			t.Errorf("%s: model provider:\n%s", c.provider, mc)
		}
		if c.model != "" && !strings.Contains(mc, c.model+"\n") {
			t.Errorf("%s: no default model %s:\n%s", c.provider, c.model, mc)
		}
		if c.provider == "openai" && (strings.Contains(mc, "model = ") || strings.Contains(mc, "web_search = 'disabled'")) {
			t.Errorf("openai route changed the model or tools:\n%s", mc)
		}
		if i, j := strings.Index(mc, "model_provider = "), strings.Index(mc, "\n["); i < 0 || i > j {
			t.Errorf("%s: model_provider is not a top-level key", c.provider)
		}
	}
}

func TestModelProvider(t *testing.T) {
	for _, c := range []struct {
		conn, flag string
		served     []string
		want       string
		err        bool
	}{
		{"codex", "", nil, "bedrock", false},
		{"codex", "", []string{"openai"}, "openai", false},
		{"codex", "", []string{"openai", "bedrock"}, "bedrock", false},
		{"codex", "openai", []string{"bedrock"}, "openai", false},
		{"codex", "bedrock", nil, "bedrock", false},
		{"codex", "bedrock-mantle", nil, "", true},
		{"codex", "anthropic", nil, "", true},
		{"claudecode", "", nil, "bedrock", false},
		{"claudecode", "", []string{"anthropic"}, "anthropic", false},
		{"claudecode", "openai", nil, "", true},
		{"opencode", "", nil, "", false},
		{"opencode", "bedrock", nil, "bedrock", false},
		{"hermes", "openai", nil, "", true},
	} {
		got, err := ModelProvider(c.conn, c.flag, c.served)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("ModelProvider(%s, %q, %v) = %q, %v; want %q, err %v", c.conn, c.flag, c.served, got, err, c.want, c.err)
		}
	}
}
