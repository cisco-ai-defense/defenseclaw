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

package sandboxcli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Record, then lock: the suggested pack extends balanced with the hosts the
// sandboxes reached that its curated list lacks. Hosts only ever refused,
// shadow AI, the blocklist feed and the model provider are left out with a
// reason; the pack validates, is never written over a file, and --diff
// names the reached hosts it would block.
func TestPolicySuggestWritesAValidPack(t *testing.T) {
	ta := newTestApp(t, "", sandboxapi.Sandbox{Name: "web", Harness: "claudecode"}, sandboxapi.Sandbox{Name: "api", Harness: "claudecode"})
	ta.daemon.destinations = map[string]*sandboxapi.Destinations{
		"web": {Name: "web", Destinations: []sandboxapi.DestinationRow{
			{Host: "artifacts.example.com", Ports: []int{443}, Kind: sandboxapi.DestinationOther, Tunnels: 12, Binaries: []string{"/usr/bin/node"}},
			{Host: "registry.npmjs.org", Ports: []int{443}, Kind: "package_registry", Tunnels: 30},
			{Host: "refused.example.net", Kind: sandboxapi.DestinationBlocked, Blocked: 2},
			{Host: "api.openai.com", Kind: sandboxapi.DestinationOtherAI, Provider: "OpenAI", Tunnels: 1},
			{Host: "pastebin.com", Kind: "paste_site", Tunnels: 1},
			{Host: "api.anthropic.com", Kind: sandboxapi.DestinationModelProvider, Connections: 50, Rule: "_provider_web"},
		}},
		"api": {Name: "api", Destinations: []sandboxapi.DestinationRow{
			{Host: "artifacts.example.com", Kind: sandboxapi.DestinationOther, Tunnels: 2, Binaries: []string{"/usr/bin/curl\n# not a comment"}},
		}},
	}
	out := filepath.Join(ta.home, "packs", "recorded", packs.PackFileName)
	ta.ok(t, ta.PolicySuggest(bg, SuggestOptions{PackOut: out}))
	has(t, ta.output(), "wrote "+out+": pack recorded, extends balanced, 1 host to allow")
	pack, err := packs.Validate(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if pack.Name != "recorded" || pack.Extends != "balanced" || pack.Network.Mode != packs.NetworkAllowlist ||
		!slices.Contains(pack.Egress.Allow, "artifacts.example.com") || slices.Contains(pack.Egress.Allow, "api.openai.com") ||
		slices.Contains(pack.Egress.Allow, "pastebin.com") || slices.Contains(pack.Egress.Allow, "api.anthropic.com") {
		t.Fatalf("pack = %+v", pack)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	has(t, text, `- "artifacts.example.com" # 14 requests; by /usr/bin/curl?# not a comment, /usr/bin/node; in api, web`,
		"# Covered by the balanced pack's curated allowlist: registry.npmjs.org",
		"#   refused.example.net: only ever refused",
		"#   api.openai.com: shadow AI (OpenAI)",
		"#   pastebin.com: on DefenseClaw's blocklist feed",
		"#   api.anthropic.com: the sandbox's model or credential provider")
	lacks(t, text, "\n# not a comment")

	if err := ta.PolicySuggest(bg, SuggestOptions{PackOut: out}); err == nil {
		t.Fatal("the suggestion wrote over a file")
	}

	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings,
		sandboxapi.Setting{Key: "network.mode", Value: "open", Source: "pack", Origin: "profile open"},
		sandboxapi.Setting{Key: "approvals.mode", Value: "auto", Source: "pack", Origin: "pack open"})
	ta.ok(t, ta.fresh().PolicySuggest(bg, SuggestOptions{Sandbox: "web", Diff: true}))
	has(t, ta.output(), "pack web-recorded against the policy of sandbox web (pack open)", "network.mode", "open → allowlist",
		"approvals.mode", "auto → triage", "reached now, blocked with the pack:", "api.openai.com — network_allowlist", "pastebin.com — feed")
	lacks(t, ta.output(), "artifacts.example.com —", "registry.npmjs.org —", "api.anthropic.com —")
}
