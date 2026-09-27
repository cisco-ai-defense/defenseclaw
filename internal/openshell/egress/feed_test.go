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

package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	feeds "github.com/defenseclaw/defenseclaw/policies/sandbox/egress"
)

func TestBuiltinFeeds(t *testing.T) {
	block, err := BuiltinBlocklist()
	if err != nil {
		t.Fatalf("BuiltinBlocklist: %v", err)
	}
	allow, err := BuiltinAllowlist()
	if err != nil {
		t.Fatalf("BuiltinAllowlist: %v", err)
	}
	if block.Kind != FeedKindBlocklist || block.Name != "defenseclaw-blocklist" || block.Version == "" {
		t.Errorf("blocklist identity = %q %q %q", block.Kind, block.Name, block.Version)
	}
	if allow.Kind != FeedKindAllowlist || allow.Name != "defenseclaw-allowlist" || allow.Version == "" {
		t.Errorf("allowlist identity = %q %q %q", allow.Kind, allow.Name, allow.Version)
	}
	sum := sha256.Sum256(feeds.BlocklistYAML())
	if block.Digest != hex.EncodeToString(sum[:]) {
		t.Errorf("blocklist digest %s does not cover the embedded bytes", block.Digest)
	}
	again, _ := BuiltinBlocklist()
	if again != block {
		t.Error("built-in feed is re-parsed on every call")
	}

	covered := map[Category]bool{}
	for _, e := range block.Entries {
		covered[e.Category] = true
		if e.Reason == "" {
			t.Errorf("entry %q has no reason", e.Name)
		}
	}
	for c := range feedCategories[FeedKindBlocklist] {
		if !covered[c] {
			t.Errorf("blocklist has no %s entries", c)
		}
	}

	blocked := map[string]Category{
		"pastebin.com":                 CategoryPasteSite,
		"www.pastebin.com":             CategoryPasteSite,
		"paste.ee":                     CategoryPasteSite,
		"api.paste.ee":                 CategoryPasteSite,
		"termbin.com":                  CategoryPasteSite,
		"transfer.sh":                  CategoryFileDrop,
		"files.catbox.moe":             CategoryFileDrop,
		"0x0.st":                       CategoryFileDrop,
		"webhook.site":                 CategoryWebhookCatcher,
		"abc123.m.pipedream.net":       CategoryWebhookCatcher,
		"xyz.oast.fun":                 CategoryWebhookCatcher,
		"abc.ngrok-free.app":           CategoryTunnel,
		"a.b.trycloudflare.com":        CategoryTunnel,
		"region1.v2.argotunnel.com":    CategoryTunnel,
		"quiet-owl.loca.lt":            CategoryTunnel,
		"host.tail1234.ts.net":         CategoryTunnel,
		"duckduckgogg42xjoc72x3.onion": CategoryAnonymizer,
		"bridges.torproject.org":       CategoryAnonymizer,
	}
	for host, want := range blocked {
		m, ok := block.Match(host)
		if !ok || m.Entry.Category != want {
			t.Errorf("blocklist.Match(%q) = %+v, %v; want %s", host, m, ok, want)
		}
	}
	for _, host := range []string{"example.com", "github.com", "registry.npmjs.org", "ngrok.com", "pipedream.net", "8.8.8.8"} {
		if m, ok := block.Match(host); ok {
			t.Errorf("blocklist.Match(%q) = %+v; want no match", host, m)
		}
	}

	allowed := map[string]Category{
		"registry.npmjs.org":        CategoryPackageRegistry,
		"files.pythonhosted.org":    CategoryPackageRegistry,
		"proxy.golang.org":          CategoryPackageRegistry,
		"github.com":                CategorySourceHosting,
		"raw.githubusercontent.com": CategorySourceHosting,
		"static.rust-lang.org":      CategoryToolchain,
		"docs.python.org":           CategoryDocumentation,
	}
	for host, want := range allowed {
		m, ok := allow.Match(host)
		if !ok || m.Entry.Category != want {
			t.Errorf("allowlist.Match(%q) = %+v, %v; want %s", host, m, ok, want)
		}
	}
}

// The curated feeds must never contradict each other.
func TestBuiltinFeedsDisjoint(t *testing.T) {
	block, _ := BuiltinBlocklist()
	allow, _ := BuiltinAllowlist()
	probe := func(pattern string) string {
		if host, ok := strings.CutPrefix(pattern, "*."); ok {
			return "probe." + host
		}
		return pattern
	}
	for _, e := range allow.Entries {
		for _, p := range e.Hosts {
			if m, ok := block.Match(probe(p)); ok {
				t.Errorf("allowlist %q (%s) is blocked by %q", p, e.Name, m.Pattern)
			}
		}
	}
	for _, e := range block.Entries {
		for _, p := range e.Hosts {
			if m, ok := allow.Match(probe(p)); ok {
				t.Errorf("blocklist %q (%s) is allowlisted by %q", p, e.Name, m.Pattern)
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
	if feed.Name != "team-feed" || len(feed.Entries) != 2 {
		t.Fatalf("feed = %+v", feed)
	}
	if feed.Entries[0].Reason != CategoryPasteSite.Reason() {
		t.Errorf("default reason = %q", feed.Entries[0].Reason)
	}
	if m, ok := feed.Match("203.0.113.9"); !ok || m.Entry.Reason != "Custom reason." || m.Pattern != "203.0.113.0/24" {
		t.Errorf("Match(203.0.113.9) = %+v, %v", m, ok)
	}

	replace := func(old, new string) string { return strings.Replace(good, old, new, 1) }
	bad := map[string]string{
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
	}
	for name, doc := range bad {
		if _, err := ParseFeed([]byte(doc)); !errors.Is(err, ErrInvalidFeed) {
			t.Errorf("%s: ParseFeed error = %v, want ErrInvalidFeed", name, err)
		}
	}
}
