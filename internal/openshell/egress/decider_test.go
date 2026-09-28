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
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// Public-looking addresses used across the tests. They are never contacted:
// the proxy tests' fake dialer routes every dial to a local listener.
const (
	publicV4    = "8.8.8.8"
	publicV4Alt = "8.8.4.4"
	publicV6    = "2001:4860:4860::8888"
)

func mustDecider(t *testing.T, opts DeciderOptions) *Decider {
	t.Helper()
	d, err := NewDecider(opts)
	if err != nil {
		t.Fatalf("NewDecider: %v", err)
	}
	return d
}

var testPrincipal = Principal{BindingID: "b-1", SandboxID: "sb-1", SandboxName: "sb-one"}

type decisionWant struct {
	allowed     bool
	category    Category
	source      Source
	rule        string
	unblockable bool
}

// Decisions the tests expect most often.
var (
	wantDefault  = decisionWant{allowed: true, source: SourceDefault}
	wantOperator = decisionWant{allowed: true, source: SourceOperator}
	wantHost     = decisionWant{category: CategoryHostInternal, source: SourceGuard}
	wantPrivate  = decisionWant{category: CategoryPrivateNetwork, source: SourceGuard}
	wantInvalid  = decisionWant{category: CategoryInvalidDestination, source: SourceGuard}
	wantPort     = decisionWant{category: CategoryPortNotAllowed, source: SourceGuard}
	wantLiteral  = decisionWant{category: CategoryIPLiteral, source: SourceDefault, unblockable: true}
	wantNotAllow = decisionWant{category: CategoryNotAllowlisted, source: SourceDefault, unblockable: true}
	wantOpBlock  = decisionWant{category: CategoryOperatorBlock, source: SourceOperator}
)

func checkDecision(t *testing.T, d *Decider, p Principal, host string, port int, want decisionWant) Decision {
	t.Helper()
	got := d.Decide(p, host, port)
	if got.Allowed != want.allowed || got.Category != want.category || got.Source != want.source ||
		(want.rule != "" && got.Rule != want.rule) || got.Unblockable != want.unblockable {
		t.Errorf("Decide(%q, %d) = %+v; want %+v", host, port, got, want)
	}
	if !got.Allowed && got.Reason == "" {
		t.Errorf("Decide(%q, %d) blocked without a reason", host, port)
	}
	return got
}

// hostsWant is the decision expected for each of hosts.
type hostsWant struct {
	want  decisionWant
	hosts []string
}

// checkHosts checks the decision on port 443 for every host of each case.
func checkHosts(t *testing.T, d *Decider, p Principal, cases []hostsWant) {
	t.Helper()
	for _, c := range cases {
		for _, host := range c.hosts {
			checkDecision(t, d, p, host, 443, c.want)
		}
	}
}

func withRule(w decisionWant, rule string) decisionWant {
	w.rule = rule
	return w
}

func TestDecideOpenMode(t *testing.T) {
	d := mustDecider(t, DeciderOptions{})
	checkHosts(t, d, testPrincipal, []hostsWant{
		{wantDefault, []string{"example.com"}},
		// Host services on addresses netguard passes as public: the Azure
		// WireServer is host-internal, its neighbour a plain literal.
		{wantLiteral, []string{publicV4, "[" + publicV6 + "]", publicV6, "::ffff:" + publicV4, "168.63.129.17"}},
		// Single-label names only the host's DNS search domains would
		// resolve are invalid.
		{wantInvalid, []string{"", "exa mple.com", "127.1", "0x7f.1", "metadata", "intranet"}},
		// Literals the guard refuses, bracketed or not: this machine and
		// what only it reaches (IPv6 metadata servers in unique local space
		// at Google and Oracle Cloud, the deprecated site-local range) ...
		{wantHost, []string{"127.0.0.1", "127.8.9.10", "169.254.169.254", "169.254.170.2", "100.100.100.200", "0.0.0.0", "0.1.2.3",
			"198.18.0.2", "192.0.2.10", "224.0.0.1", "240.0.0.1", "255.255.255.255", "168.63.129.16",
			"[::1]", "::", "[fe80::1]", "fe80::1%eth0", "[fd00:ec2::254]", "[fd20:ce::254]", "[fd00:c1::a9fe:a9fe]", "[fec0::1]",
			"[feff:ffff::1]", "[::ffff:127.0.0.1]", "[::ffff:169.254.169.254]", "[::127.0.0.1]", "[64:ff9b::7f00:1]",
			"[2002:7f00:1::1]", "[2001:db8::1]", "[ff02::1]",
			// ... and names host-internal by definition ...
			"localhost", "LOCALHOST.", "api.localhost", "myhost.localdomain", "host.openshell.internal", "x.openshell.internal",
			"host.docker.internal", "host.containers.internal", "metadata.google.internal"}},
		// ... private networks and intranet names.
		{wantPrivate, []string{"10.0.0.1", "172.16.5.4", "192.168.1.1", "100.64.0.1", "[fc00::1]", "[fd00::1]", "[fd20:ce::253]",
			"[::ffff:10.1.2.3]", "artifactory.corp.internal", "printer.local", "router.home.arpa", "nas.lan", "build.corp"}},
	})
	for _, tt := range []struct {
		host string
		port int
		want decisionWant
	}{
		{"EXAMPLE.com.", 80, wantDefault},
		{"169.254.169.254", 80, wantHost},
		{"webhook.site", 443, decisionWant{category: CategoryWebhookCatcher, source: SourceFeed, rule: "webhook.site", unblockable: true}},
		{"abc.ngrok-free.app", 443, decisionWant{category: CategoryTunnel, source: SourceFeed, rule: "*.ngrok-free.app", unblockable: true}},
		{"pastebin.com", 80, decisionWant{category: CategoryPasteSite, source: SourceFeed, unblockable: true}},
		{"example.com", 22, wantPort},
		{"example.com", 8443, wantPort},
		{"example.com", 0, wantInvalid},
		{"example.com", 70000, wantInvalid},
	} {
		checkDecision(t, d, testPrincipal, tt.host, tt.port, tt.want)
	}

	got := d.Decide(testPrincipal, "webhook.site", 443)
	if got.Feed != "defenseclaw-blocklist" || got.FeedVersion == "" || got.Entry != "Webhook.site" || got.Mode != ModeOpen {
		t.Errorf("feed provenance = %+v", got)
	}
	if got := d.Decide(testPrincipal, "example.com", 22); !strings.Contains(got.Reason, "80, 443") {
		t.Errorf("port reason %q does not list the allowed ports", got.Reason)
	}
	if got := d.Decide(testPrincipal, "bad\r\nhost", 443); strings.ContainsAny(got.Host, "\r\n") {
		t.Errorf("invalid host echoed unsanitized: %q", got.Host)
	}
}

// The operator's private-upstream allowlist exists for the daemon's own
// upstreams and must never widen what a sandbox can reach.
func TestDecideIgnoresDaemonPrivateAllowlist(t *testing.T) {
	netguard.SetAllowedPrivateIPs([]net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("100.64.0.9")})
	t.Cleanup(func() { netguard.SetAllowedPrivateIPs(nil) })
	checkHosts(t, mustDecider(t, DeciderOptions{}), testPrincipal, []hostsWant{{wantPrivate, []string{"10.0.0.5", "100.64.0.9"}}})
}

// In open mode a public IP literal needs an operator allow or an unblock: a
// literal sidesteps the name-based blocklist (CONNECT to a CDN address, then
// any blocked site's server name).
func TestDecideIPLiterals(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: publicV4, SandboxID: "sb-1"}, Unblock{Pattern: "2001:4860::/32"})
	must(t, err)
	builtin, err := BuiltinBlocklist()
	must(t, err)
	d := mustDecider(t, DeciderOptions{Unblocks: unblocks, Allow: []string{"1.1.1.0/24"}, Blocklists: []*Feed{builtin, testFeedCIDR(t)}})
	other := Principal{BindingID: "b-2", SandboxID: "sb-2"}

	if got := checkDecision(t, d, other, publicV4, 443, wantLiteral); got.Host != publicV4 || !strings.Contains(got.Reason, "blocklist") {
		t.Errorf("ip_literal decision = %+v", got)
	}
	checkDecision(t, d, testPrincipal, publicV4, 443, decisionWant{allowed: true, source: SourceUnblock, rule: publicV4})
	checkDecision(t, d, other, publicV6, 443, decisionWant{allowed: true, source: SourceUnblock, rule: "2001:4860::/32"})
	checkDecision(t, d, other, "1.1.1.1", 443, withRule(wantOperator, "1.1.1.0/24"))
	// A feed's CIDR entry keeps its own category; names are unaffected.
	checkDecision(t, d, other, publicV4Alt, 443, decisionWant{category: CategoryFileDrop, source: SourceFeed, rule: "8.8.4.0/24", unblockable: true})
	checkDecision(t, d, other, "example.com", 443, wantDefault)

	// Allowlist mode already refuses literals as not allowlisted; a
	// principal in open mode on an allowlist decider gets ip_literal.
	a := mustDecider(t, DeciderOptions{Mode: ModeAllowlist})
	checkDecision(t, a, other, publicV4, 443, wantNotAllow)
	open := other
	open.Mode = ModeOpen
	checkDecision(t, a, open, publicV4, 443, wantLiteral)
}

// This machine's own public addresses are refused by the guard, which
// neither operator allows nor unblocks can lift. Other hosts on its public
// subnets (the /64 of a global IPv6 address, the prefix of a public IPv4
// one) are its local network.
func TestDecideOwnAddresses(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: ownV4}, Unblock{Pattern: ownV6})
	must(t, err)
	d := mustDecider(t, DeciderOptions{Allow: []string{ownV4, publicV4}, Unblocks: unblocks})
	d.local = fixedLocalAddrs(ownV4, ownV6)
	for reason, tc := range map[string]struct {
		want  decisionWant
		hosts []string
	}{
		"belongs to this machine": {wantHost, []string{ownV4, "::ffff:" + ownV4, ownV6, "[" + ownV6 + "]"}},
		"own subnets":             {wantPrivate, []string{"2620:fe::1", "[2620:fe::ffff:2]", "9.9.200.1", "::ffff:9.9.0.1"}},
	} {
		for _, host := range tc.hosts {
			for _, port := range []int{80, 443} {
				if got := checkDecision(t, d, testPrincipal, host, port, tc.want); !strings.Contains(got.Reason, reason) {
					t.Errorf("Decide(%s) reason = %q", host, got.Reason)
				}
			}
		}
	}
	// Names are checked against their answers at dial time, not here.
	checkHosts(t, d, testPrincipal, []hostsWant{
		{wantOperator, []string{publicV4}}, {wantDefault, []string{"example.com"}}, {wantLiteral, []string{"2620:fe:0:1::1"}},
	})
}

// Private networks open only through the operator's allow list: a pattern
// for the name, or an IP or CIDR no wider than the private range or on-link
// subnet it covers. Unblocks never open them, operator blocks still win,
// and nothing opens this machine itself or what only it can reach.
func TestDecidePrivateNetworksOpenThroughOperatorAllow(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: "10.9.0.0/16"}, Unblock{Pattern: "db.lan"})
	must(t, err)
	d := mustDecider(t, DeciderOptions{
		Mode:     ModeAllowlist,
		Unblocks: unblocks,
		Allow: []string{
			"10.20.0.0/16", "192.168.1.50", "fd12:3456::/32", "2620:fe::/64", "100.64.0.0/10",
			"*.corp", "artifactory.example.internal", "0.0.0.0/0", "::/0", "172.0.0.0/8",
			"127.0.0.1", "localhost", "*.openshell.internal", "metadata.google.internal", "169.254.169.254", ownV4,
			"fd20:ce::/32", "fd20:ce::254", "168.63.129.16", "fec0::/10",
		},
		Block: []string{"10.20.9.9", "blocked.corp"},
	})
	d.local = fixedLocalAddrs(ownV4, ownV6)
	for host, rule := range map[string]string{
		"10.20.3.4": "10.20.0.0/16", "192.168.1.50": "192.168.1.50", "[fd12:3456::1]": "fd12:3456::/32", "2620:fe::1": "2620:fe::/64",
		"100.100.1.1": "100.64.0.0/10", "git.corp": "*.corp", "artifactory.example.internal": "artifactory.example.internal",
		"8.8.8.8": "0.0.0.0/0", "[fd20:ce::1]": "fd20:ce::/32",
	} {
		checkDecision(t, d, testPrincipal, host, 443, withRule(wantOperator, rule))
	}
	checkHosts(t, d, testPrincipal, []hostsWant{
		// Operator blocks still win over an opened private destination.
		{withRule(wantOpBlock, "10.20.9.9"), []string{"10.20.9.9"}},
		{withRule(wantOpBlock, "blocked.corp"), []string{"blocked.corp"}},
	})
	for _, tc := range []struct {
		want  decisionWant
		hint  string
		hosts []string
	}{
		// Wider than the private range (0.0.0.0/0, ::/0 and 172.0.0.0/8 open
		// public literals only), or only unblocked: still closed.
		{wantPrivate, "openshell.egress.allow", []string{"10.1.2.3", "172.16.0.1", "[fd00::1]", "192.168.1.51", "9.9.200.1", "10.9.1.1", "db.lan", "nas.lan"}},
		// This machine and what only it reaches stay closed.
		{wantHost, "--host-port", []string{"127.0.0.1", "localhost", "host.openshell.internal", "metadata.google.internal", "169.254.169.254",
			ownV4, "[fd20:ce::254]", "168.63.129.16", "[fec0::1]"}},
	} {
		for _, host := range tc.hosts {
			if hint := DefaultUnblockHint(testPrincipal, checkDecision(t, d, testPrincipal, host, 443, tc.want)); !strings.Contains(hint, tc.hint) {
				t.Errorf("Decide(%s) hint = %q", host, hint)
			}
		}
	}
}

// The private-network hint names only entries openshell.egress.allow
// accepts, and each of them opens the destination it is meant for: the
// configuration takes names, "*." wildcards and single IP addresses, not
// CIDRs. With openshell.admin.allow_unblock: false the sandbox policy drops
// the allow entries the user adds, so the hint must name the administrator
// instead.
func TestPrivateNetworkHintMatchesConfig(t *testing.T) {
	hint := DefaultUnblockHint(testPrincipal, Decision{Host: "wiki.example.com", Port: 443, Category: CategoryPrivateNetwork})
	for _, want := range []string{"openshell.egress.allow", "exact host name", "IP address", "*.corp"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint %q does not mention %q", hint, want)
		}
	}
	if strings.Contains(hint, "CIDR") || strings.Contains(hint, "/8") {
		t.Errorf("hint %q suggests a CIDR, which openshell.egress.allow rejects", hint)
	}
	// Config also accepts CIDR prefixes (the proxy's pattern grammar); the
	// hint deliberately suggests the simplest entries that open one private
	// destination: the exact name, its address, or an intranet wildcard.
	g, r, _ := newTestGuard(t)
	r.set("wiki.example.com", []string{"10.9.9.9"})
	r.set("git.corp", []string{"10.9.9.10"})
	for _, tt := range []struct{ allow, host string }{
		{"wiki.example.com", "wiki.example.com"}, {"10.9.9.9", "wiki.example.com"}, {"10.9.9.9", "10.9.9.9"}, {"*.corp", "git.corp"},
		{"fd00::9", "[fd00::9]"},
	} {
		if err := config.ValidateOpenShellEgressPattern(tt.allow); err != nil {
			t.Errorf("config rejects the hinted entry %q: %v", tt.allow, err)
		}
		d := mustDecider(t, DeciderOptions{Allow: []string{tt.allow}})
		d.local = g.local
		dec := d.Decide(testPrincipal, tt.host, 443)
		if !dec.Allowed {
			t.Errorf("allow %q: Decide(%s) = %+v", tt.allow, tt.host, dec)
			continue
		}
		if conn, _, err := g.dial(context.Background(), dec.Host, dec.Port, d.dialRules(testPrincipal, dec)); err != nil {
			t.Errorf("allow %q: dial(%s) = %v", tt.allow, tt.host, err)
		} else {
			_ = conn.Close()
		}
	}

	d := mustDecider(t, DeciderOptions{NoUnblock: true})
	d.local = fixedLocalAddrs(ownV4, ownV6)
	for _, host := range []string{"10.9.9.9", "wiki.corp"} {
		dec := d.Decide(testPrincipal, host, 443)
		hint := DefaultUnblockHint(testPrincipal, dec)
		if dec.Category != CategoryPrivateNetwork || !dec.NoUnblock || strings.Contains(hint, "openshell.egress.allow") ||
			strings.Contains(hint, "sandbox unblock") || !strings.Contains(hint, "administrator") || !strings.Contains(hint, "openshell.admin.egress_allow_only") {
			t.Errorf("without unblocking: Decide(%s) = %+v, hint %q", host, dec, hint)
		}
	}
}

func TestDecideAllowlistMode(t *testing.T) {
	d := mustDecider(t, DeciderOptions{Mode: ModeAllowlist})
	got := checkDecision(t, d, testPrincipal, "registry.npmjs.org", 443, decisionWant{allowed: true, category: CategoryPackageRegistry, source: SourceFeed})
	if got.Feed != "defenseclaw-allowlist" || got.Entry == "" || got.Mode != ModeAllowlist {
		t.Errorf("allowlist provenance = %+v", got)
	}
	checkHosts(t, d, testPrincipal, []hostsWant{
		{decisionWant{allowed: true, category: CategorySourceHosting, source: SourceFeed}, []string{"objects.githubusercontent.com"}},
		{wantNotAllow, []string{"example.com", publicV4}},
		{decisionWant{category: CategoryWebhookCatcher, source: SourceFeed, unblockable: true}, []string{"webhook.site"}},
		{wantHost, []string{"localhost"}},
	})
	// A principal's own mode wins over the decider default.
	open, balanced := testPrincipal, testPrincipal
	open.Mode, balanced.Mode = ModeOpen, ModeAllowlist
	checkDecision(t, d, open, "example.com", 443, wantDefault)
	checkDecision(t, mustDecider(t, DeciderOptions{}), balanced, "example.com", 443, wantNotAllow)
}

func TestDecideOperatorLists(t *testing.T) {
	d := mustDecider(t, DeciderOptions{
		Block: []string{"example.com", "*.corp-exfil.net", "8.8.4.0/24", "both.example.org"},
		Allow: []string{"webhook.site", "both.example.org", "127.0.0.1", "*.partner.example.net"},
	})
	for host, rule := range map[string]string{"example.com": "example.com", "a.b.corp-exfil.net": "*.corp-exfil.net", publicV4Alt: "8.8.4.0/24", "both.example.org": "both.example.org"} {
		checkDecision(t, d, testPrincipal, host, 443, withRule(wantOpBlock, rule))
	}
	// Operator allow overrides the feed ... but never the guard.
	checkDecision(t, d, testPrincipal, "webhook.site", 443, withRule(wantOperator, "webhook.site"))
	checkDecision(t, d, testPrincipal, "127.0.0.1", 443, wantHost)
	checkDecision(t, d, testPrincipal, "webhook.site", 22, wantPort)

	// Operator allow admits destinations in allowlist mode.
	a := mustDecider(t, DeciderOptions{Mode: ModeAllowlist, Allow: []string{"*.partner.example.net"}})
	checkHosts(t, a, testPrincipal, []hostsWant{{wantOperator, []string{"api.partner.example.net"}}, {wantNotAllow, []string{"partner.example.net"}}})
}

// TestDecideAdminLists pins where the administrator's lists sit: after the
// guard and the ports, before the block list and every unblock, and never
// unblockable.
func TestDecideAdminLists(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: "a.ngrok.io"}, Unblock{Pattern: "pypi.org"}, Unblock{Pattern: "x.pastebin.com"})
	must(t, err)
	d := mustDecider(t, DeciderOptions{
		AdminBlock: []string{"*.ngrok.io", "8.8.4.0/24"},
		AllowOnly:  []string{"*.ngrok.io", "*.pastebin.com", "git.corp", "8.8.8.8", "wiki.corp.example"},
		Block:      []string{"wiki.corp.example"},
		Allow:      []string{"a.ngrok.io"},
		Unblocks:   unblocks,
	})
	admin := decisionWant{category: CategoryAdminBlock, source: SourceAdmin}
	outside := decisionWant{category: CategoryAdminAllowOnly, source: SourceAdmin}
	checkHosts(t, d, testPrincipal, []hostsWant{
		{withRule(admin, "*.ngrok.io"), []string{"a.ngrok.io"}},
		{withRule(admin, "8.8.4.0/24"), []string{publicV4Alt}},
		{outside, []string{"pypi.org", "example.com"}},
		// Inside the allow-only list the block list, the feed and the guard
		// still apply; unblocks lift only the feed.
		{wantOpBlock, []string{"wiki.corp.example"}},
		{decisionWant{allowed: true, source: SourceUnblock}, []string{"x.pastebin.com"}},
		{decisionWant{category: CategoryPasteSite, source: SourceFeed, unblockable: true}, []string{"y.pastebin.com"}},
		{wantHost, []string{"localhost"}},
		// An allow-only entry allows, opens the intranet name it names, and
		// admits an IP literal in either mode.
		{decisionWant{allowed: true, source: SourceAdmin, rule: "git.corp"}, []string{"git.corp"}},
		{decisionWant{allowed: true, source: SourceAdmin, rule: "8.8.8.8"}, []string{publicV4}},
	})
	checkDecision(t, d, testPrincipal, "git.corp", 22, wantPort)
	a := mustDecider(t, DeciderOptions{Mode: ModeAllowlist, AllowOnly: []string{"*.example.org"}, Allowlists: []*Feed{}})
	checkHosts(t, a, testPrincipal, []hostsWant{
		{decisionWant{allowed: true, source: SourceAdmin, rule: "*.example.org"}, []string{"docs.example.org"}},
		{outside, []string{"registry.npmjs.org"}},
	})
	if got := d.Decide(testPrincipal, "a.ngrok.io", 443); !strings.Contains(got.Reason, "your organization's DefenseClaw policy") {
		t.Errorf("admin block reason = %q", got.Reason)
	}
	if hint := DefaultUnblockHint(testPrincipal, d.Decide(testPrincipal, "pypi.org", 443)); !strings.Contains(hint, "organization") ||
		strings.Contains(hint, "sandbox unblock") {
		t.Errorf("admin hint = %q", hint)
	}
}

// TestDecideNoUnblock pins openshell.admin.allow_unblock: false: unblocks
// are ignored, nothing is reported unblockable, and the feed wins over the
// allow list.
func TestDecideNoUnblock(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: "webhook.site"}, Unblock{Pattern: "example.com"})
	must(t, err)
	d := mustDecider(t, DeciderOptions{NoUnblock: true, Unblocks: unblocks, Allow: []string{"x.pastebin.com", "docs.example.org"}})
	if d.UnblocksAllowed() {
		t.Fatal("UnblocksAllowed with NoUnblock")
	}
	checkHosts(t, d, testPrincipal, []hostsWant{
		{decisionWant{category: CategoryWebhookCatcher, source: SourceFeed}, []string{"webhook.site"}},
		{decisionWant{category: CategoryPasteSite, source: SourceFeed}, []string{"x.pastebin.com"}},
		{wantOperator, []string{"docs.example.org"}},
		{decisionWant{category: CategoryIPLiteral, source: SourceDefault}, []string{publicV4}},
	})
	a := mustDecider(t, DeciderOptions{Mode: ModeAllowlist, NoUnblock: true, Unblocks: unblocks})
	checkDecision(t, a, testPrincipal, "example.com", 443, decisionWant{category: CategoryNotAllowlisted, source: SourceDefault})
	for _, host := range []string{"webhook.site", publicV4} {
		if hint := DefaultUnblockHint(testPrincipal, d.Decide(testPrincipal, host, 443)); strings.Contains(hint, "sandbox unblock") ||
			(host == "webhook.site" && !strings.Contains(hint, "organization")) {
			t.Errorf("%s hint without unblocking = %q", host, hint)
		}
	}
	// Dial time: an allow entry no longer lifts a feed CIDR either.
	withCIDR := mustDecider(t, DeciderOptions{NoUnblock: true, Blocklists: []*Feed{testFeedCIDR(t)}, Allow: []string{"cdn.example", publicV4Alt}})
	dec := withCIDR.Decide(testPrincipal, "cdn.example", 443)
	if got := withCIDR.CheckAddrs(testPrincipal, dec, []netip.Addr{netip.MustParseAddr(publicV4Alt)}); !dec.Allowed || got.Allowed || got.Unblockable {
		t.Fatalf("feed CIDR at dial time without unblocking = %+v (name %+v)", got, dec)
	}
}

func TestDecideHostSkipsPorts(t *testing.T) {
	d := mustDecider(t, DeciderOptions{Ports: []int{443}})
	if got := d.DecideHost(testPrincipal, "example.com"); !got.Allowed || got.Port != 0 {
		t.Fatalf("DecideHost = %+v", got)
	}
	checkDecision(t, d, testPrincipal, "example.com", 80, wantPort)
	for host, want := range map[string]Category{
		"webhook.site": CategoryWebhookCatcher, "localhost": CategoryHostInternal, "10.0.0.1": CategoryPrivateNetwork,
		"intranet": CategoryInvalidDestination, publicV4: CategoryIPLiteral,
	} {
		if got := d.DecideHost(testPrincipal, host); got.Allowed || got.Category != want {
			t.Errorf("DecideHost(%s) = %+v, want %s", host, got, want)
		}
	}
}

// TestCheckAddrs pins the dial-time rules callers apply to what a name
// resolves to before they open a path the proxy does not guard.
func TestCheckAddrs(t *testing.T) {
	d := mustDecider(t, DeciderOptions{
		Blocklists: []*Feed{testFeedCIDR(t)},
		AdminBlock: []string{"8.8.8.0/29"},
		Block:      []string{"1.1.1.0/24"},
		Allow:      []string{"db.partner.example"},
	})
	addrs := func(list ...string) []netip.Addr {
		var out []netip.Addr
		for _, a := range list {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	for _, tc := range []struct {
		host   string
		addrs  []netip.Addr
		want   Category
		source Source
	}{
		{"ok.example", addrs("9.9.9.9", "2620:fe::fe"), "", ""},
		{"loop.example", addrs("9.9.9.9", "127.0.0.1"), CategoryHostInternal, SourceGuard},
		{"meta.example", addrs("169.254.169.254"), CategoryHostInternal, SourceGuard},
		{"zoned.example", []netip.Addr{netip.MustParseAddr("fe80::1").WithZone("eth0")}, CategoryHostInternal, SourceGuard},
		{"lan.example", addrs("10.0.0.5"), CategoryPrivateNetwork, SourceGuard},
		{"db.partner.example", addrs("10.0.0.6"), "", ""},
		{"admin.example", addrs("8.8.8.3"), CategoryAdminBlock, SourceAdmin},
		{"op.example", addrs("1.1.1.1"), CategoryOperatorBlock, SourceOperator},
		{"drop.example", addrs(publicV4Alt), CategoryFileDrop, SourceFeed},
	} {
		dec := d.Decide(testPrincipal, tc.host, 443)
		if !dec.Allowed {
			t.Fatalf("Decide(%s) = %+v", tc.host, dec)
		}
		if got := d.CheckAddrs(testPrincipal, dec, tc.addrs); got.Allowed != (tc.want == "") ||
			(tc.want != "" && (got.Category != tc.want || got.Source != tc.source || got.Reason == "")) {
			t.Errorf("CheckAddrs(%s) = %+v, want %q from %q", tc.host, got, tc.want, tc.source)
		}
	}
	// A refusal is returned as is.
	refused := d.Decide(testPrincipal, "webhook.site", 443)
	if got := d.CheckAddrs(testPrincipal, refused, addrs("9.9.9.9")); got != refused {
		t.Fatalf("CheckAddrs of a refusal = %+v", got)
	}
}

func TestLookupHost(t *testing.T) {
	r := newFakeResolver()
	r.set("cdn.example", []string{"9.9.9.9", "::ffff:8.8.8.8", "2620:fe::fe"})
	r.set("empty.example", nil)
	r.fail("gone.example", errors.New("no such host"))
	ctx := context.Background()
	got, err := LookupHost(ctx, r, "CDN.Example.")
	if err != nil || len(got) != 3 || got[1] != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("LookupHost = %v, %v", got, err)
	}
	if names := r.names(); len(names) != 1 || names[0] != "cdn.example." {
		t.Fatalf("looked up %v, want the fully qualified name", names)
	}
	if got, err := LookupHost(ctx, r, "[2001:4860:4860::8888]"); err != nil || len(got) != 1 || got[0] != netip.MustParseAddr(publicV6) {
		t.Fatalf("LookupHost of a literal = %v, %v", got, err)
	}
	for _, host := range []string{"gone.example", "bad host", "empty.example"} {
		if _, err := LookupHost(ctx, r, host); err == nil || (host == "empty.example" && !errors.Is(err, ErrNoAddresses)) {
			t.Errorf("LookupHost(%q) = %v", host, err)
		}
	}
}

func TestDecideUnblocks(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(
		Unblock{Pattern: "webhook.site", SandboxID: "sb-1"}, Unblock{Pattern: "*.NGROK-FREE.app"},
		Unblock{Pattern: "example.com"}, Unblock{Pattern: "localhost"}, Unblock{Pattern: "10.0.0.0/8"},
	)
	must(t, err)
	d := mustDecider(t, DeciderOptions{Unblocks: unblocks, Block: []string{"example.com"}})
	unblocked := decisionWant{allowed: true, source: SourceUnblock}
	feed := decisionWant{category: CategoryWebhookCatcher, source: SourceFeed, unblockable: true}
	checkDecision(t, d, testPrincipal, "webhook.site", 443, withRule(unblocked, "webhook.site"))
	checkDecision(t, d, Principal{BindingID: "b-2", SandboxID: "sb-2"}, "webhook.site", 443, feed)
	checkDecision(t, d, Principal{BindingID: "b-3"}, "webhook.site", 443, feed)
	checkDecision(t, d, Principal{BindingID: "b-2", SandboxID: "sb-2"}, "x.ngrok-free.app", 443, withRule(unblocked, "*.ngrok-free.app"))
	// Unblocks never lift operator or guard blocks.
	checkHosts(t, d, testPrincipal, []hostsWant{{wantOpBlock, []string{"example.com"}}, {wantHost, []string{"localhost"}}, {wantPrivate, []string{"10.1.2.3"}}})
	// In allowlist mode an unblock admits a not-allowlisted destination.
	checkDecision(t, mustDecider(t, DeciderOptions{Mode: ModeAllowlist, Unblocks: unblocks}), testPrincipal, "example.com", 443, withRule(unblocked, "example.com"))
}

func TestMemoryUnblocks(t *testing.T) {
	m, err := NewMemoryUnblocks()
	must(t, err)
	if err := m.Add(Unblock{Pattern: "bad host"}); !errors.Is(err, ErrInvalidPattern) {
		t.Fatalf("Add(bad) = %v", err)
	}
	must(t, m.Add(Unblock{Pattern: "Webhook.Site", SandboxID: "sb-1"}))
	must(t, m.Add(Unblock{Pattern: "webhook.site", SandboxID: "sb-1"})) // replaces
	must(t, m.Add(Unblock{Pattern: "webhook.site"}))
	must(t, m.Add(Unblock{Pattern: "paste.ee", SandboxID: "sb-1"}))
	must(t, m.Add(Unblock{Pattern: "paste.ee", SandboxID: "sb-2"}))
	if n := len(m.List()); n != 4 {
		t.Fatalf("List() has %d entries, want 4: %+v", n, m.List())
	}
	if u, ok := m.Unblocked(testPrincipal, "WEBHOOK.site."); !ok || u.SandboxID != "sb-1" {
		t.Errorf("sandbox-scoped unblock not preferred: %+v %v", u, ok)
	}
	if !m.Remove("sb-1", "WEBHOOK.SITE") || m.Remove("sb-1", "webhook.site") {
		t.Error("Remove did not remove exactly once")
	}
	if u, ok := m.Unblocked(testPrincipal, "webhook.site"); !ok || u.SandboxID != "" {
		t.Errorf("persistent unblock not used: %+v %v", u, ok)
	}
	if n := m.RemoveSandbox("sb-1"); n != 1 || m.RemoveSandbox("") != 0 {
		t.Errorf("RemoveSandbox = %d, want 1 (and none for the persistent ones)", n)
	}
	before := m.List()
	if err := m.Replace([]Unblock{{Pattern: "ok.example"}, {Pattern: "*"}}); err == nil || !slices.Equal(before, m.List()) {
		t.Fatalf("Replace with an invalid pattern = %v and changed the set", err)
	}
	must(t, m.Replace(nil))
	for _, host := range []string{"webhook.site", "bad host"} {
		if _, ok := m.Unblocked(testPrincipal, host); ok {
			t.Errorf("Unblocked(%q) after Replace(nil)", host)
		}
	}
}

func TestNewDeciderValidation(t *testing.T) {
	block, _ := BuiltinBlocklist()
	allow, _ := BuiltinAllowlist()
	for name, opts := range map[string]DeciderOptions{
		"mode":           {Mode: "deny"},
		"port zero":      {Ports: []int{0}},
		"port range":     {Ports: []int{443, 65536}},
		"block pattern":  {Block: []string{"*"}},
		"allow pattern":  {Allow: []string{"a.*.com"}},
		"blocklist kind": {Blocklists: []*Feed{allow}},
		"allowlist kind": {Allowlists: []*Feed{block}},
		"nil feed":       {Blocklists: []*Feed{nil}},
		"unparsed feed":  {Blocklists: []*Feed{{Kind: FeedKindBlocklist}}},
	} {
		if _, err := NewDecider(opts); err == nil {
			t.Errorf("%s: NewDecider accepted %+v", name, opts)
		}
	}

	d := mustDecider(t, DeciderOptions{Ports: []int{8443, 443, 443}})
	if got := d.Ports(); !slices.Equal(got, []int{443, 8443}) || d.Mode() != ModeOpen {
		t.Errorf("Ports() = %v, Mode() = %q", got, d.Mode())
	}
	checkDecision(t, d, testPrincipal, "example.com", 8443, wantDefault)
	checkDecision(t, d, testPrincipal, "example.com", 80, wantPort)
	if infos := d.Feeds(); len(infos) != 2 || infos[0].Kind != FeedKindBlocklist || infos[1].Kind != FeedKindAllowlist || infos[0].Digest == "" {
		t.Errorf("Feeds() = %+v", infos)
	}
	// An empty feed list disables the built-in feed.
	checkDecision(t, mustDecider(t, DeciderOptions{Blocklists: []*Feed{}}), testPrincipal, "webhook.site", 443, wantDefault)

	// Extra feeds apply in order after the first.
	team, err := ParseFeed([]byte("schema_version: 1\nkind: blocklist\nname: team\nfeed_version: \"7\"\nentries:\n" +
		"  - {name: Team drop, category: file_drop, hosts: [drop.example.org, webhook.site]}\n"))
	must(t, err)
	both := mustDecider(t, DeciderOptions{Blocklists: []*Feed{block, team}})
	if got := both.Decide(testPrincipal, "drop.example.org", 443); got.Feed != "team" || got.FeedVersion != "7" {
		t.Errorf("team feed decision = %+v", got)
	}
	if got := both.Decide(testPrincipal, "webhook.site", 443); got.Feed != "defenseclaw-blocklist" {
		t.Errorf("first feed did not win: %+v", got)
	}
}

func TestModes(t *testing.T) {
	for in, want := range map[string]Mode{"open": ModeOpen, " Allowlist ": ModeAllowlist} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("balanced"); err == nil {
		t.Error("ParseMode accepted a profile name")
	}
	for _, p := range []struct {
		profile string
		mode    Mode
		enabled bool
		bad     bool
	}{
		{"", ModeOpen, true, false},
		{"open", ModeOpen, true, false},
		{"Balanced", ModeAllowlist, true, false},
		{"strict", "", false, false},
		{"yolo", "", false, true},
	} {
		mode, enabled, err := ModeForProfile(p.profile)
		if (err != nil) != p.bad || mode != p.mode || enabled != p.enabled {
			t.Errorf("ModeForProfile(%q) = %q, %v, %v", p.profile, mode, enabled, err)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for isAddr, cases := range map[bool]map[string]string{
		false: {"Example.COM.": "example.com", "  registry.npmjs.org ": "registry.npmjs.org",
			"under_score.example.com": "under_score.example.com", "xn--p1ai": "xn--p1ai"},
		true: {"8.8.8.8": "8.8.8.8", "[2001:DB8::1]": "2001:db8::1", "2001:db8::1": "2001:db8::1", "::ffff:127.0.0.1": "127.0.0.1",
			"[::ffff:10.0.0.1]": "10.0.0.1", "fe80::1%eth0": "fe80::1%eth0"},
	} {
		for in, want := range cases {
			if got, addr, err := normalizeHost(in); err != nil || got != want || addr.IsValid() != isAddr {
				t.Errorf("normalizeHost(%q) = %q, addr=%v, %v; want %q addr=%v", in, got, addr, err, want, isAddr)
			}
		}
	}
	for _, in := range []string{
		"", ".", "a..b.com", ".example.com", "exa mple.com", "user@example.com", "example.com:443", "例え.jp",
		// Numeric forms that are not dotted-quad literals, and all-numeric
		// top-level labels.
		"127.1", "0x7f.1", "0x7f000001", "2130706433", "017700000001", "1.2.3.4.", "example.123",
		strings.Repeat("a", 64) + ".com", strings.Repeat("abcdefghi.", 26) + "com",
	} {
		if got, _, err := normalizeHost(in); !errors.Is(err, ErrInvalidHost) {
			t.Errorf("normalizeHost(%q) = %q, %v; want ErrInvalidHost", in, got, err)
		}
	}
}

func TestParsePattern(t *testing.T) {
	for _, tt := range []struct {
		in, raw string
		kind    patternKind
	}{
		{"Example.com", "example.com", patternExact},
		{"*.Ngrok-Free.App.", "*.ngrok-free.app", patternSuffix},
		{"8.8.8.8", "8.8.8.8", patternPrefix},
		{"[2001:db8::1]", "2001:db8::1", patternPrefix},
		{"10.1.2.3/8", "10.0.0.0/8", patternPrefix},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8", patternPrefix},
		{"2001:db8::/32", "2001:db8::/32", patternPrefix},
	} {
		if p, err := parsePattern(tt.in); err != nil || p.raw != tt.raw || p.kind != tt.kind {
			t.Errorf("parsePattern(%q) = %+v, %v; want raw %q kind %d", tt.in, p, err, tt.raw, tt.kind)
		}
	}
	for _, in := range []string{"", "*", "*.", "**.example.com", "a.*.example.com", "example.*", "*.8.8.8.8", "10.0.0.0/33",
		"::ffff:10.0.0.0/64", "fe80::1%eth0", "bad host"} {
		if p, err := parsePattern(in); !errors.Is(err, ErrInvalidPattern) {
			t.Errorf("parsePattern(%q) = %+v, %v; want ErrInvalidPattern", in, p, err)
		}
	}
}

func TestHostSetMatch(t *testing.T) {
	set := newHostSet[string]()
	for _, raw := range []string{"*.example.com", "api.example.com", "*.eu.example.com", "8.8.0.0/16", "8.8.8.0/24", "2001:db8::/32"} {
		p, err := parsePattern(raw)
		must(t, err)
		if !set.add(p, raw) {
			t.Fatalf("add(%q) reported a duplicate", raw)
		}
	}
	if dup, _ := parsePattern("API.example.com"); set.add(dup, "dup") || set.len() != 6 {
		t.Fatalf("a duplicate pattern was added (len %d)", set.len())
	}
	for host, want := range map[string]string{ // "" = no match
		"api.example.com": "api.example.com", "www.example.com": "*.example.com", "a.b.c.example.com": "*.example.com",
		"x.eu.example.com": "*.eu.example.com", "example.com": "", "notexample.com": "", "example.com.evil.net": "",
		"8.8.8.8": "8.8.8.0/24", "8.8.4.4": "8.8.0.0/16", "9.9.9.9": "", "2001:db8::5": "2001:db8::/32", "::ffff:8.8.8.8": "8.8.8.0/24",
	} {
		host, addr, err := normalizeHost(host)
		must(t, err)
		if item, ok := set.match(host, addr); ok != (want != "") || item.value != want {
			t.Errorf("match(%q) = %q, %v; want %q", host, item.value, ok, want)
		}
	}
	// A single pattern matches the same way; a zoned address never matches
	// a prefix.
	for _, c := range []struct {
		pattern, host string
		want          bool
	}{
		{"example.com", "example.com", true}, {"example.com", "www.example.com", false}, {"*.example.com", "www.example.com", true},
		{"*.example.com", "example.com", false}, {"8.8.8.0/24", "8.8.8.8", true}, {"8.8.8.0/24", "example.com", false},
		{"example.com", "8.8.8.8", false},
	} {
		p, err := parsePattern(c.pattern)
		must(t, err)
		if host, addr, _ := normalizeHost(c.host); p.matches(host, addr) != c.want {
			t.Errorf("%q.matches(%q) != %v", c.pattern, c.host, c.want)
		}
	}
	zoned := netip.MustParseAddr("fe80::1%eth0")
	if p, _ := parsePattern("fe80::/10"); p.matches(zoned.String(), zoned) {
		t.Error("zoned address matched a prefix")
	}
}
