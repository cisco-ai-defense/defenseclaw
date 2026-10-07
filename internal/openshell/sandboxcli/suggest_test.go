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

//go:build !windows

package sandboxcli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Record, then lock: the suggested pack extends balanced with the hosts the
// sandboxes reached that its curated list lacks. Hosts only ever refused,
// shadow AI, the blocklist feed, the model provider and a --credential
// endpoint (even one another sandbox reached as a plain host) are left out
// with a reason; the pack validates, is never written over a file, and
// --diff names the reached hosts it would block.
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
			{Host: "api.stripe.com", Ports: []int{443}, Kind: sandboxapi.DestinationCredential, Connections: 3, Rule: "_provider_web_cred"},
		}},
		"api": {Name: "api", Destinations: []sandboxapi.DestinationRow{
			{Host: "artifacts.example.com", Kind: sandboxapi.DestinationOther, Tunnels: 2, Binaries: []string{"/usr/bin/curl\n# not a comment"}},
			{Host: "api.stripe.com", Ports: []int{443}, Kind: sandboxapi.DestinationOther, Tunnels: 1},
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
		slices.Contains(pack.Egress.Allow, "pastebin.com") || slices.Contains(pack.Egress.Allow, "api.anthropic.com") ||
		slices.Contains(pack.Egress.Allow, "api.stripe.com") {
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
		"#   api.anthropic.com: the sandbox's model provider opens it",
		"#   api.stripe.com: a --credential binding of the sandbox opens it directly to the programs it binds")
	lacks(t, text, `- "api.stripe.com"`)
	lacks(t, text, "\n# not a comment")

	if err := ta.PolicySuggest(bg, SuggestOptions{PackOut: out}); err == nil {
		t.Fatal("the suggestion wrote over a file")
	}
	// GAP-0126: written into the project folder (a relative --pack-out run
	// there), the pack is one a mounted run refuses; the hint said to run
	// with it anyway.
	ta.ok(t, ta.fresh().PolicySuggest(bg, SuggestOptions{PackOut: "recorded.yaml"}))
	has(t, ta.output(), "is inside the project folder, where a run that mounts the project refuses a pack",
		"then move it to ", "and lock the project to it: defenseclaw sandbox run --pack recorded (or run with --copy --pack ")
	lacks(t, ta.output(), "lock a project to it: defenseclaw sandbox run --pack /")

	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings,
		sandboxapi.Setting{Key: "network.mode", Value: "open", Source: "pack", Origin: "profile open"},
		sandboxapi.Setting{Key: "approvals.mode", Value: "auto", Source: "pack", Origin: "pack open"})
	// GAP-0112: a MicroVM gateway holds the sandbox to a copy, which the
	// diff listed as "workdir.mode copy → mount", a change no run gets. The
	// sandbox's policy names the gateway's driver as the source, or the
	// --copy that `sandbox run` passes on such a gateway (round 2): a flag
	// decides it whatever the pack says.
	for _, copied := range []sandboxapi.Setting{
		{Key: "workdir.mode", Value: "copy", Source: string(packs.SourceGateway), Origin: "compute driver", Requested: "mount"},
		{Key: "workdir.mode", Value: "copy", Source: string(packs.SourceFlag), Origin: "--copy"},
	} {
		for i := range ta.daemon.explain.Settings {
			if ta.daemon.explain.Settings[i].Key == "workdir.mode" {
				ta.daemon.explain.Settings[i] = copied
			}
		}
		ta.ok(t, ta.fresh().PolicySuggest(bg, SuggestOptions{Sandbox: "web", Diff: true}))
		has(t, ta.output(), "pack web-recorded against the policy of sandbox web (pack open)", "network.mode", "open → allowlist",
			"approvals.mode", "auto → triage", "reached now, blocked with the pack:", "api.openai.com — network_allowlist", "pastebin.com — feed")
		lacks(t, ta.output(), "artifacts.example.com —", "registry.npmjs.org —", "api.anthropic.com —", "api.stripe.com —", "workdir.mode")
	}
}

// A recorded host that is not a host name is whatever text the sandbox's
// traffic carried. Listed in a comment of the pack, a YAML line break in it
// (NEL, U+2028, U+2029) cannot set pack keys, and a character the YAML
// reader refuses (U+FFFE) does not break the pack.
func TestPolicySuggestKeepsRecordedHostsInComments(t *testing.T) {
	ls, ps, nel, nonchar := "\xe2\x80\xa8", "\xe2\x80\xa9", "\xc2\x85", "\xef\xbf\xbe"
	ta := newTestApp(t, "", sandboxapi.Sandbox{Name: "web", Harness: "claudecode"})
	ta.daemon.destinations = map[string]*sandboxapi.Destinations{"web": {Name: "web", Destinations: []sandboxapi.DestinationRow{
		{Host: "artifacts.example.com", Kind: sandboxapi.DestinationOther, Tunnels: 1},
		{Host: "x" + ls + "network: {mode: open}" + ls + "approvals: {mode: auto}" + ls + "#", Kind: sandboxapi.DestinationBlocked, Blocked: 1},
		{Host: "y" + ps + "egress: {ports: [22]}" + nel + "#", Kind: sandboxapi.DestinationOtherAI, Provider: "P" + ls + "q", Tunnels: 1},
		{Host: "z" + nonchar + ".example", Kind: sandboxapi.DestinationBlocked, Blocked: 1},
	}}}
	out := filepath.Join(ta.home, "recorded.yaml")
	ta.ok(t, ta.PolicySuggest(bg, SuggestOptions{PackOut: out}))
	pack, err := packs.Validate(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if pack.Network.Mode != packs.NetworkAllowlist || pack.Approvals.Mode != packs.ApprovalsTriage || !slices.Equal(pack.Egress.Ports, []int{80, 443}) {
		t.Fatalf("a recorded host set pack keys: network %s, approvals %s, ports %v", pack.Network.Mode, pack.Approvals.Mode, pack.Egress.Ports)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	has(t, string(data), "#   x?network: {mode: open}?approvals: {mode: auto}?#: only ever refused",
		"#   y?egress: {ports: [22]}?#: shadow AI (P?q)", "#   z?.example: only ever refused")
	lacks(t, string(data), ls, ps, nel, nonchar)
	ta.ok(t, ta.fresh().PolicySuggest(bg, SuggestOptions{}))
	has(t, ta.output(), "#   x?network: {mode: open}")
	lacks(t, ta.output(), ls, ps, nel, nonchar)
}

// --pack-out takes a path relative to this folder, and a "~/" the shell
// left as typed, as `run --pack` would read them; a written pack that does
// not validate is removed with the folders made for it.
func TestPolicySuggestPackOutPaths(t *testing.T) {
	ta := newTestApp(t, "", sandboxapi.Sandbox{Name: "web", Harness: "claudecode"})
	ta.daemon.destinations = map[string]*sandboxapi.Destinations{"web": {Name: "web", Destinations: []sandboxapi.DestinationRow{
		{Host: "artifacts.example.com", Kind: sandboxapi.DestinationOther, Tunnels: 1}}}}
	ta.ok(t, ta.PolicySuggest(bg, SuggestOptions{PackOut: "rel/recorded.yaml"}))
	rel := filepath.Join(ta.project, "rel", "recorded.yaml")
	has(t, ta.output(), "wrote "+rel+": pack recorded", "--copy --pack "+rel)
	ta.ok(t, ta.fresh().PolicySuggest(bg, SuggestOptions{PackOut: "~/team/pack.yaml"}))
	if p, err := packs.Validate(filepath.Join(ta.home, "team", packs.PackFileName), ""); err != nil || p.Name != "team" {
		t.Fatalf("~/team/pack.yaml: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(ta.project, "~")); err == nil {
		t.Fatal("a folder named ~ was made")
	}

	// A folder every user can write to: the pack would not load from it.
	shared := filepath.Join(ta.home, "shared")
	if err := os.Mkdir(shared, 0o755); err != nil || os.Chmod(shared, 0o777) != nil {
		t.Fatal(err)
	}
	wantErr(t, ta.fresh().PolicySuggest(bg, SuggestOptions{PackOut: filepath.Join(shared, "pack.yaml")}), "the written pack does not validate", "writable by every user")
	if _, err := os.Lstat(filepath.Join(shared, "pack.yaml")); err == nil {
		t.Fatal("the pack that does not validate was kept")
	}
	undo, err := writeNewFile(filepath.Join(ta.home, "a", "b", "pack.yaml"), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	undo()
	if _, err := os.Lstat(filepath.Join(ta.home, "a")); err == nil {
		t.Fatal("undo kept the folders it made")
	}
}

// A suggested pack holds what a pack can: 1024 allow entries with
// balanced's, and 64 KiB. The most requested hosts stay, the others are
// listed apart and named on stderr. Ports beyond balanced's that the
// allowed hosts were reached on are added, unless the host was also
// refused (perhaps for the port).
func TestPolicySuggestFitsThePack(t *testing.T) {
	balanced, err := packs.Builtin("balanced")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, label string
		hosts       int
	}{{"entries", "h", 1100}, {"bytes", strings.Repeat("a", 58), 900}} {
		t.Run(c.name, func(t *testing.T) {
			rows := []sandboxapi.DestinationRow{
				{Host: "artifacts.example.net", Ports: []int{443, 8443}, Kind: sandboxapi.DestinationOther, Tunnels: 5000},
				{Host: "flaky.example.net", Ports: []int{443, 9000}, Kind: sandboxapi.DestinationOther, Tunnels: 4000, Blocked: 1},
			}
			for i := range c.hosts {
				rows = append(rows, sandboxapi.DestinationRow{Host: fmt.Sprintf("%s%04d.example.com", c.label, i), Kind: sandboxapi.DestinationOther, Tunnels: int64(i + 1)})
			}
			ta := newTestApp(t, "", sandboxapi.Sandbox{Name: "web", Harness: "claudecode"})
			ta.daemon.destinations = map[string]*sandboxapi.Destinations{"web": {Name: "web", Destinations: rows}}
			out := filepath.Join(ta.home, "recorded.yaml")
			ta.ok(t, ta.PolicySuggest(bg, SuggestOptions{PackOut: out}))
			pack, err := packs.Validate(out, "")
			if err != nil {
				t.Fatal(err)
			}
			least, most := fmt.Sprintf("%s%04d.example.com", c.label, 0), fmt.Sprintf("%s%04d.example.com", c.label, c.hosts-1)
			if !slices.Contains(pack.Egress.Allow, "artifacts.example.net") || !slices.Contains(pack.Egress.Allow, most) ||
				slices.Contains(pack.Egress.Allow, least) {
				t.Fatalf("kept %d allow entries, not the most requested", len(pack.Egress.Allow))
			}
			if c.name == "entries" && len(pack.Egress.Allow) != packs.MaxListEntries {
				t.Fatalf("allow entries = %d, want %d (%d of them balanced's)", len(pack.Egress.Allow), packs.MaxListEntries, len(balanced.Egress.Allow))
			}
			if !slices.Equal(pack.Egress.Ports, []int{80, 443, 8443}) {
				t.Fatalf("ports = %v", pack.Egress.Ports)
			}
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			has(t, string(data), "# Not suggested, no room in the pack (a pack holds 1024 allow entries", "#   "+least+": no room in the pack",
				"8443 (artifacts.example.net)", "  ports: [80, 443, 8443]", "Not opened", "flaky.example.net:9000")
			has(t, ta.err.String(), "did not fit in the pack")
		})
	}
}
