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

package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
	feeds "github.com/defenseclaw/defenseclaw/policies/sandbox/egress"
)

func TestBuiltinFeeds(t *testing.T) {
	block, err := BuiltinBlocklist()
	must(t, err)
	allow, err := BuiltinAllowlist()
	must(t, err)
	if block.Kind != FeedKindBlocklist || block.Name != "defenseclaw-blocklist" || block.Version == "" {
		t.Errorf("blocklist identity = %q %q %q", block.Kind, block.Name, block.Version)
	}
	if allow.Kind != FeedKindAllowlist || allow.Name != "defenseclaw-allowlist" || allow.Version == "" {
		t.Errorf("allowlist identity = %q %q %q", allow.Kind, allow.Name, allow.Version)
	}
	if sum := sha256.Sum256(feeds.BlocklistYAML()); block.Digest != hex.EncodeToString(sum[:]) {
		t.Errorf("blocklist digest %s does not cover the embedded bytes", block.Digest)
	}
	if again, _ := BuiltinBlocklist(); again != block {
		t.Error("built-in feed is re-parsed on every call")
	}

	covered := map[Category]bool{}
	for _, e := range block.Entries {
		covered[e.Category] = true
		if e.Reason == "" {
			t.Errorf("entry %q has no reason", e.Name)
		}
		// Every exact host has its "*." companion in the same entry, so the
		// service's API, upload and www hosts are blocked with it.
		for _, p := range e.Hosts {
			if !strings.HasPrefix(p, "*.") && !slices.Contains(e.Hosts, "*."+p) {
				t.Errorf("blocklist entry %q lists %s without *.%s", e.Name, p, p)
			}
		}
	}
	for c := range feedCategories[FeedKindBlocklist] {
		if !covered[c] {
			t.Errorf("blocklist has no %s entries", c)
		}
	}

	for want, hosts := range map[Category][]string{
		CategoryPasteSite: {"pastebin.com", "www.pastebin.com", "paste.ee", "api.paste.ee", "termbin.com", "api.paste.gg",
			"www.controlc.com", "www.justpaste.it", "api.rentry.co"},
		CategoryFileDrop:       {"transfer.sh", "files.catbox.moe", "0x0.st", "www.0x0.st", "upload.tmpfiles.org"},
		CategoryWebhookCatcher: {"webhook.site", "abc123.m.pipedream.net", "xyz.oast.fun"},
		CategoryTunnel:         {"abc.ngrok-free.app", "a.b.trycloudflare.com", "region1.v2.argotunnel.com", "quiet-owl.loca.lt", "host.tail1234.ts.net"},
		CategoryAnonymizer:     {"duckduckgogg42xjoc72x3.onion", "bridges.torproject.org"},
	} {
		for _, host := range hosts {
			if m, ok := block.Match(host); !ok || m.Entry.Category != want {
				t.Errorf("blocklist.Match(%q) = %+v, %v; want %s", host, m, ok, want)
			}
		}
	}
	for _, host := range []string{"example.com", "github.com", "registry.npmjs.org", "ngrok.com", "pipedream.net", "8.8.8.8"} {
		if m, ok := block.Match(host); ok {
			t.Errorf("blocklist.Match(%q) = %+v; want no match", host, m)
		}
	}
	for host, want := range map[string]Category{
		"registry.npmjs.org": CategoryPackageRegistry, "files.pythonhosted.org": CategoryPackageRegistry,
		"proxy.golang.org": CategoryPackageRegistry, "github.com": CategorySourceHosting,
		"raw.githubusercontent.com": CategorySourceHosting, "static.rust-lang.org": CategoryToolchain,
		"docs.python.org": CategoryDocumentation,
	} {
		if m, ok := allow.Match(host); !ok || m.Entry.Category != want {
			t.Errorf("allowlist.Match(%q) = %+v, %v; want %s", host, m, ok, want)
		}
	}

	// The curated feeds must never contradict each other.
	probe := func(pattern string) string {
		if host, ok := strings.CutPrefix(pattern, "*."); ok {
			return "probe." + host
		}
		return pattern
	}
	for _, pair := range [][2]*Feed{{allow, block}, {block, allow}} {
		for _, e := range pair[0].Entries {
			for _, p := range e.Hosts {
				if m, ok := pair[1].Match(probe(p)); ok {
					t.Errorf("%s %q (%s) is also in the %s as %q", pair[0].Kind, p, e.Name, pair[1].Kind, m.Pattern)
				}
			}
		}
	}
}

func TestParseFeed(t *testing.T) {
	const good = `
schema_version: 1
kind: blocklist
name: team-feed
feed_version: "1"
entries:
  - name: Example paste
    category: paste_site
    hosts: [paste.example.org, "*.paste.example.org"]
  - name: Example drop
    category: file_drop
    reason: Custom reason.
    hosts: [drop.example.org, 203.0.113.0/24]
`
	feed, err := ParseFeed([]byte(good))
	if err != nil {
		t.Fatalf("ParseFeed: %v", err)
	}
	if feed.Name != "team-feed" || len(feed.Entries) != 2 || feed.Entries[0].Reason != CategoryPasteSite.Reason() {
		t.Fatalf("feed = %+v", feed)
	}
	if m, ok := feed.Match("203.0.113.9"); !ok || m.Entry.Reason != "Custom reason." || m.Pattern != "203.0.113.0/24" {
		t.Errorf("Match(203.0.113.9) = %+v, %v", m, ok)
	}

	replace := func(old, new string) string { return strings.Replace(good, old, new, 1) }
	for name, doc := range map[string]string{
		"schema version":       replace("schema_version: 1", "schema_version: 2"),
		"unknown kind":         replace("kind: blocklist", "kind: denylist"),
		"missing name":         replace("name: team-feed\n", ""),
		"bad name":             replace("name: team-feed", "name: Team Feed"),
		"bad version":          replace(`feed_version: "1"`, `feed_version: "1 2"`),
		"no entries":           "schema_version: 1\nkind: blocklist\nname: x\nfeed_version: \"1\"\nentries: []\n",
		"entry without name":   replace("  - name: Example paste\n", "  - name: \"\"\n"),
		"unknown category":     replace("category: paste_site", "category: gambling"),
		"allowlist category":   replace("category: paste_site", "category: package_registry"),
		"no hosts":             replace(`hosts: [paste.example.org, "*.paste.example.org"]`, "hosts: []"),
		"bad pattern":          replace("drop.example.org,", "drop.*.example.org,"),
		"duplicate pattern":    replace("drop.example.org,", "PASTE.example.org,"),
		"unknown field":        replace("kind: blocklist", "kind: blocklist\nowner: me"),
		"second document":      good + "---\nfoo: bar\n",
		"not yaml":             "{{{",
		"oversized":            good + "# " + strings.Repeat("x", maxFeedBytes),
		"allowlist kind check": replace("kind: blocklist", "kind: allowlist"),
	} {
		if _, err := ParseFeed([]byte(doc)); !errors.Is(err, ErrInvalidFeed) {
			t.Errorf("%s: ParseFeed error = %v, want ErrInvalidFeed", name, err)
		}
	}
}

func TestFirewallBlockPatterns(t *testing.T) {
	cfg := &firewall.FirewallConfig{Rules: []firewall.Rule{
		{Name: "metadata", Direction: "outbound", Protocol: "tcp", Destination: "169.254.169.254", Action: "deny"},
		{Name: "host", Destination: "Exfil.Example.com", Action: "DENY"},
		{Name: "wildcard", Protocol: "any", Destination: "*.bad.example.net", Action: "deny"},
		{Name: "cidr", Destination: "8.8.4.0/24", Action: "deny"},
		{Name: "dup", Destination: "exfil.example.com", Action: "deny"},
		{Name: "allow rule", Destination: "ok.example.com", Action: "allow"},
		{Name: "udp only", Protocol: "udp", Destination: "dns.example.com", Action: "deny"},
		{Name: "inbound", Direction: "inbound", Destination: "in.example.com", Action: "deny"},
		{Name: "no destination", Port: 22, Action: "deny"},
		{Name: "ssh only", Destination: "ssh.example.com", Port: 22, Action: "deny"},
		{Name: "https", Destination: "tls.example.com", Port: 443, Action: "deny"},
		{Name: "range", Destination: "range.example.com", PortRange: "400-500", Action: "deny"},
		{Name: "colon range", Destination: "colon.example.com", PortRange: "1:79", Action: "deny"},
		{Name: "bad range", Destination: "odd.example.com", PortRange: "web", Action: "deny"},
		{Name: "bad destination", Destination: "a.*.example.com", Action: "deny"},
	}}
	got := FirewallBlockPatterns(cfg, nil)
	if want := []string{"169.254.169.254", "exfil.example.com", "*.bad.example.net", "8.8.4.0/24", "tls.example.com", "range.example.com", "odd.example.com"}; !slices.Equal(got, want) {
		t.Errorf("FirewallBlockPatterns = %v\nwant %v", got, want)
	}
	if got := FirewallBlockPatterns(cfg, []int{22}); !slices.Contains(got, "ssh.example.com") || slices.Contains(got, "tls.example.com") {
		t.Errorf("port-scoped rules with ports [22] = %v", got)
	}
	if FirewallBlockPatterns(nil, nil) != nil {
		t.Error("nil config produced patterns")
	}
	// The output is always accepted by the Decider.
	checkDecision(t, mustDecider(t, DeciderOptions{Block: got}), testPrincipal, "x.bad.example.net", 443, wantOpBlock)

	// The shipped default firewall config converts cleanly. It denies by
	// default and allowlists DefenseClaw's own endpoints; neither the
	// default action nor the allowlist carries over to sandboxes.
	def := firewall.DefaultFirewallConfig()
	got = FirewallBlockPatterns(def, nil)
	if !slices.Contains(got, "169.254.169.254") {
		t.Errorf("default firewall config = %v", got)
	}
	for _, host := range slices.Concat(def.Allowlist.Domains, def.Allowlist.IPs) {
		if slices.Contains(got, host) {
			t.Errorf("allowlisted %s became a sandbox block pattern", host)
		}
	}
	denyAll := &firewall.FirewallConfig{DefaultAction: "deny", Allowlist: firewall.AllowlistConfig{Domains: []string{"api.github.com"}}}
	if got := FirewallBlockPatterns(denyAll, nil); len(got) != 0 {
		t.Errorf("default_action deny with an allowlist = %v, want no patterns", got)
	}

	for in, want := range map[string][2]int{"443": {443, 443}, "1000-2000": {1000, 2000}, " 80 : 90 ": {80, 90}} {
		if lo, hi, ok := parsePortRange(in); !ok || lo != want[0] || hi != want[1] {
			t.Errorf("parsePortRange(%q) = %d, %d, %v", in, lo, hi, ok)
		}
	}
	for _, in := range []string{"", "x", "0-10", "10-5", "1-70000", "a-b"} {
		if _, _, ok := parsePortRange(in); ok {
			t.Errorf("parsePortRange(%q) accepted", in)
		}
	}
}
