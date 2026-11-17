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

package kit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// GAP-0413: a Codex template asked GPT-5.6 Luna (a Bedrock model id) on the
// openai route (/llm/openai/v1), which a Bedrock install does not serve, so
// every model call failed with provider_credential_unavailable. The build
// now refuses that pair; Luna on the bedrock route and a vendor model name
// on the openai route still build.
func TestGAP0413BedrockModelOnAVendorRouteIsRefused(t *testing.T) {
	art, err := SubstrateArtifacts(harness.Codex.Provider, harness.Codex.DefaultVersion, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	build := func(provider, model string) error {
		_, err := ActorOverlay(art, OverlayOptions{Config: DefaultConfig(), Home: "/sandbox", Workdir: "/work",
			Provider: provider, Model: model, HarnessVersion: "2.1.300"})
		return err
	}
	if err := build("openai", LunaModel); err == nil || !strings.Contains(err.Error(), "--provider bedrock") {
		t.Fatalf("Luna on the openai route built: %v", err)
	}
	for _, c := range []struct{ provider, model string }{{"bedrock", LunaModel}, {"bedrock", ""}, {"openai", "gpt-5.6"}, {"openai", ""}} {
		if err := build(c.provider, c.model); err != nil {
			t.Fatalf("%s %q: %v", c.provider, c.model, err)
		}
	}
}
