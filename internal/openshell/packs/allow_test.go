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

package packs

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// testFeed stands in for the egress proxy's builtin exfiltration feed.
func testFeed(feeds []string, host string) (string, bool) {
	if containsString(feeds, FeedBuiltin) && (host == "webhook.site" || host == "raw.githubusercontent.com" ||
		strings.HasSuffix(host, ".pastebin.com")) {
		return "exfil:" + host, true
	}
	return "", false
}

func withHostname(t *testing.T, name string) {
	t.Helper()
	previous := osHostname
	osHostname = func() (string, error) { return name, nil }
	t.Cleanup(func() { osHostname = previous })
}

func TestAllowActions(t *testing.T) {
	withHostname(t, "DevBox.corp.example")
	type outcome struct {
		constraint string // "" allows; "error" is a plain (non-Violation) refusal
		fatal      bool
	}
	allowed := outcome{}
	invalid := outcome{constraint: "error"}
	for _, tc := range []struct {
		name   string
		edit   func(*config.OpenShellConfig)
		flags  Flags
		action Action
		want   outcome
	}{
		{"unblock by default", nil, Flags{}, Action{Kind: ActionUnblock, Host: "webhook.site"}, allowed},
		{"unblock off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionUnblock, Host: "webhook.site"}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"unblock admin-blocked host", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"*.ngrok.io"} }, Flags{},
			Action{Kind: ActionUnblock, Host: "Abc.NGROK.io."}, outcome{constraint: "openshell.admin.egress_block"}},
		{"unblock outside allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			Action{Kind: ActionUnblock, Host: "pypi.org"}, outcome{constraint: "openshell.admin.egress_allow_only"}},
		{"unblock inside allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			Action{Kind: ActionUnblock, Host: "git.corp.example"}, allowed},
		{"unblock under the strict profile", nil, Flags{Profile: "strict"},
			Action{Kind: ActionUnblock, Host: "pypi.org"}, outcome{constraint: "profile strict"}},
		{"unblock under an admin-forced strict profile", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "strict" }, Flags{},
			Action{Kind: ActionUnblock, Host: "pypi.org"}, outcome{constraint: "openshell.admin.min_profile"}},
		{"unblock a glob", nil, Flags{}, Action{Kind: ActionUnblock, Host: "*.example.com"}, invalid},
		{"unblock nothing", nil, Flags{}, Action{Kind: ActionUnblock}, invalid},
		{"unblock a URL", nil, Flags{}, Action{Kind: ActionUnblock, Host: "https://x.example"}, invalid},

		{"approve once", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443, Feed: testFeed}, allowed},
		{"approve once without a feed matcher", nil, Flags{},
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443}, allowed},
		{"approve once without a feed matcher when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443}, invalid},
		{"approve a blocklisted host", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"paste.example"} }, Flags{},
			Action{Kind: ActionApprove, Host: "paste.example", Port: 443, Feed: testFeed}, allowed},
		{"approve a blocklisted host when unblock is off", func(o *config.OpenShellConfig) {
			o.Egress.Block, o.Admin.AllowUnblock = []string{"paste.example"}, boolPtr(false)
		}, Flags{}, Action{Kind: ActionApprove, Host: "Paste.Example.", Port: 443, Feed: testFeed}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve a feed host", nil, Flags{}, Action{Kind: ActionApprove, Host: "webhook.site", Port: 443, Feed: testFeed}, allowed},
		{"approve a feed host when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "webhook.site", Port: 443, Feed: testFeed}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve a feed host with the feed off", func(o *config.OpenShellConfig) { o.Egress.Feed = "none" }, Flags{},
			Action{Kind: ActionApprove, Host: "webhook.site", Port: 443}, allowed},
		{"approve a private address", nil, Flags{}, Action{Kind: ActionApprove, Host: "10.0.0.5", Port: 5432}, allowed},
		{"approve a private address when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "10.0.0.5", Port: 5432, Feed: testFeed}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve a CGNAT address when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "100.64.1.2", Port: 443, Feed: testFeed}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve the metadata address", nil, Flags{}, Action{Kind: ActionApprove, Host: "169.254.169.254", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve a mapped metadata address", nil, Flags{}, Action{Kind: ActionApprove, Host: "[::ffff:169.254.169.254]", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve the IPv6 metadata address", nil, Flags{}, Action{Kind: ActionApprove, Host: "fd00:ec2::254", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve the Alibaba metadata address", nil, Flags{}, Action{Kind: ActionApprove, Host: "100.100.100.200", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve a metadata name", nil, Flags{}, Action{Kind: ActionApprove, Host: "Metadata.Google.Internal", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve a link-local address", nil, Flags{}, Action{Kind: ActionApprove, Host: "fe80::1", Port: 22}, outcome{constraint: "defenseclaw"}},
		{"approve multicast", nil, Flags{}, Action{Kind: ActionApprove, Host: "224.0.0.251", Port: 5353}, outcome{constraint: "defenseclaw"}},
		{"approve a short IPv4 spelling", nil, Flags{}, Action{Kind: ActionApprove, Host: "127.1", Port: 18970}, invalid},
		{"approve a decimal IPv4 spelling", nil, Flags{}, Action{Kind: ActionApprove, Host: "2130706433", Port: 18970}, invalid},
		{"approve a hex IPv4 spelling", nil, Flags{}, Action{Kind: ActionApprove, Host: "0x7f000001", Port: 18970}, invalid},
		{"approve an octal IPv4 spelling", nil, Flags{}, Action{Kind: ActionApprove, Host: "0177.0.0.1", Port: 18970}, invalid},
		{"unblock a short IPv4 spelling", nil, Flags{}, Action{Kind: ActionUnblock, Host: "10.1"}, invalid},
		{"approve ip6-localhost", nil, Flags{}, Action{Kind: ActionApprove, Host: "ip6-localhost", Port: 18970}, outcome{constraint: "defenseclaw"}},
		{"approve localhost.localdomain", nil, Flags{}, Action{Kind: ActionApprove, Host: "localhost.localdomain", Port: 18970}, outcome{constraint: "defenseclaw"}},
		{"approve the Docker host alias", nil, Flags{}, Action{Kind: ActionApprove, Host: "host.docker.internal", Port: OpenShellGatewayPort}, outcome{constraint: "defenseclaw"}},
		{"approve this machine by name", nil, Flags{}, Action{Kind: ActionApprove, Host: "devbox", Port: 18971}, outcome{constraint: "defenseclaw"}},
		{"approve this machine by mDNS name", nil, Flags{}, Action{Kind: ActionApprove, Host: "devbox.local", Port: 18972}, outcome{constraint: "defenseclaw"}},
		{"approve this machine by full name", nil, Flags{}, Action{Kind: ActionApprove, Host: "devbox.corp.example.", Port: 18972}, outcome{constraint: "defenseclaw"}},
		{"approve a mapped loopback address", nil, Flags{}, Action{Kind: ActionApprove, Host: "::ffff:127.0.0.1", Port: 18970}, outcome{constraint: "defenseclaw"}},
		{"approve another loopback address with host ports off", func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "127.0.0.2", Port: 5432}, outcome{constraint: "openshell.admin.allow_host_ports"}},
		{"approve ip6-loopback with host ports off", func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "ip6-loopback", Port: 5432}, outcome{constraint: "openshell.admin.allow_host_ports"}},
		{"approve an admin-blocked host", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"api.example.com"} }, Flags{},
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443}, outcome{constraint: "openshell.admin.egress_block"}},
		{"approve always", nil, Flags{}, Action{Kind: ActionApproveAlways, Host: "api.example.com", Port: 443}, allowed},
		{"approve always off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApproveAlways, Host: "api.example.com"}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve the host alias", nil, Flags{}, Action{Kind: ActionApprove, Host: OpenShellHostAlias, Port: 5432}, allowed},
		{"approve the OpenShell gateway", nil, Flags{},
			Action{Kind: ActionApprove, Host: OpenShellHostAlias, Port: OpenShellGatewayPort}, outcome{constraint: "defenseclaw"}},
		{"approve loopback API", nil, Flags{},
			Action{Kind: ActionApproveAlways, Host: "127.0.0.1", Port: 18970}, outcome{constraint: "defenseclaw"}},
		{"approve localhost without port", nil, Flags{}, Action{Kind: ActionApprove, Host: "localhost"}, invalid},
		{"approve host with host ports off", func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "[::1]", Port: 5432}, outcome{constraint: "openshell.admin.allow_host_ports"}},
		{"approve bad port", nil, Flags{}, Action{Kind: ActionApprove, Host: "api.example.com", Port: 70000}, invalid},

		{"host port", nil, Flags{}, Action{Kind: ActionHostPort, Port: 5432}, allowed},
		{"host port reserved", nil, Flags{}, Action{Kind: ActionHostPort, Port: 18972}, outcome{constraint: "defenseclaw"}},
		{"host port admin off", func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, Flags{},
			Action{Kind: ActionHostPort, Port: 5432}, outcome{constraint: "openshell.admin.allow_host_ports"}},
		{"host port strict pack", nil, Flags{Pack: "strict"}, Action{Kind: ActionHostPort, Port: 5432}, outcome{constraint: "pack strict"}},
		{"host port zero", nil, Flags{}, Action{Kind: ActionHostPort}, invalid},

		{"mount", nil, Flags{}, Action{Kind: ActionMount, Path: "/src/app"}, allowed},
		{"mount off", func(o *config.OpenShellConfig) { o.Admin.AllowMount = boolPtr(false) }, Flags{},
			Action{Kind: ActionMount, Path: "/src/app"}, outcome{constraint: "openshell.admin.allow_mount"}},
		{"mount a copy-only project", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-*"} }, Flags{},
			Action{Kind: ActionMount, Path: "/src/customer-a/lib"}, outcome{constraint: "openshell.admin.require_copy_for"}},
		{"mount a parent of a copy-only project", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-acme"} }, Flags{Copy: true},
			Action{Kind: ActionMount, Path: "/src"}, outcome{constraint: "openshell.admin.require_copy_for"}},
		{"mount a copy-only project spelled in another case", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-acme"} }, Flags{Copy: true},
			Action{Kind: ActionMount, Path: "/SRC/Customer-ACME/app"}, outcome{constraint: "openshell.admin.require_copy_for"}},
		{"mount a sibling of a copy-only project", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-acme"} }, Flags{Copy: true},
			Action{Kind: ActionMount, Path: "/src/internal"}, allowed},
		{"mount relative", nil, Flags{}, Action{Kind: ActionMount, Path: "lib"}, invalid},

		{"yolo", nil, Flags{}, Action{Kind: ActionYolo}, allowed},
		{"yolo off", func(o *config.OpenShellConfig) { o.Admin.AllowYolo = boolPtr(false) }, Flags{},
			Action{Kind: ActionYolo}, outcome{constraint: "openshell.admin.allow_yolo"}},
		{"learn", nil, Flags{}, Action{Kind: ActionLearnMode}, allowed},
		{"learn off", func(o *config.OpenShellConfig) { o.Admin.AllowLearnMode = boolPtr(false) }, Flags{},
			Action{Kind: ActionLearnMode}, outcome{constraint: "openshell.admin.allow_learn_mode"}},

		{"harness", nil, Flags{}, Action{Kind: ActionHarness, Harness: "codex"}, allowed},
		{"harness refused", func(o *config.OpenShellConfig) { o.Admin.AllowedHarnesses = []string{"codex"} }, Flags{},
			Action{Kind: ActionHarness, Harness: "Claude-Code"}, outcome{constraint: "openshell.admin.allowed_harnesses", fatal: true}},
		{"harness malformed", nil, Flags{}, Action{Kind: ActionHarness, Harness: "a b"}, invalid},

		{"unknown action", nil, Flags{}, Action{Kind: "teleport"}, invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, _ := mustResolve(t, testConfig(tc.edit), tc.flags)
			err := eff.Allow(tc.action)
			var v *Violation
			isViolation := errors.As(err, &v)
			switch {
			case tc.want == allowed:
				if err != nil {
					t.Fatalf("Allow(%+v) = %v, want nil", tc.action, err)
				}
			case tc.want == invalid:
				if err == nil || isViolation {
					t.Fatalf("Allow(%+v) = %v, want a plain error", tc.action, err)
				}
			default:
				if !isViolation || v.Constraint != tc.want.constraint || v.Fatal != tc.want.fatal || v.Source != SourceUser {
					t.Fatalf("Allow(%+v) = %#v, want constraint %q", tc.action, err, tc.want.constraint)
				}
				if v.Admin() && !strings.HasPrefix(v.Message, "blocked by your organization's DefenseClaw policy: ") {
					t.Fatalf("admin message = %q", v.Message)
				}
				if v.Message == "" || v.Detail == "" || v.Attempted == "" && tc.action.Kind != ActionYolo && tc.action.Kind != ActionLearnMode {
					t.Fatalf("violation lacks text: %+v", v)
				}
			}
		})
	}

	var nilEff *Effective
	if err := nilEff.Allow(Action{Kind: ActionYolo}); err == nil {
		t.Fatal("a nil Effective must refuse every action")
	}
}

func TestAllowMessages(t *testing.T) {
	eff, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		o.Admin.EgressBlock = []string{"*.ngrok.io"}
	}), Flags{})
	err := eff.Allow(Action{Kind: ActionUnblock, Host: "x.ngrok.io"})
	want := "blocked by your organization's DefenseClaw policy: egress.unblock (x.ngrok.io matches *.ngrok.io on your organization's blocklist)"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	err = eff.Allow(Action{Kind: ActionHostPort, Port: 17670})
	if err == nil || !strings.HasPrefix(err.Error(), "DefenseClaw never opens the OpenShell gateway (port 17670) to a sandbox") {
		t.Fatalf("error = %v", err)
	}
	strict, _ := mustResolve(t, testConfig(nil), Flags{Profile: "strict"})
	err = strict.Allow(Action{Kind: ActionUnblock, Host: "pypi.org"})
	if err == nil || !strings.HasPrefix(err.Error(), "not allowed by the strict sandbox profile: egress.unblock") {
		t.Fatalf("error = %v", err)
	}
}

func TestDecideEgress(t *testing.T) {
	feed := testFeed
	for _, tc := range []struct {
		name        string
		edit        func(*config.OpenShellConfig)
		flags       Flags
		host        string
		port        int
		allowed     bool
		rule        EgressRule
		match       string
		unblockable bool
	}{
		{"open web", nil, Flags{}, "example.org", 443, true, RuleNetworkOpen, "", false},
		{"feed hit", nil, Flags{}, "WEBHOOK.site.", 443, false, RuleFeed, "exfil:webhook.site", true},
		{"feed off", func(o *config.OpenShellConfig) { o.Egress.Feed = "none" }, Flags{}, "webhook.site", 443, true, RuleNetworkOpen, "", false},
		{"allow exempts from the feed", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"webhook.site"} }, Flags{},
			"webhook.site", 443, true, RuleAllow, "webhook.site", false},
		{"user block", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"*.example.org"} }, Flags{},
			"cdn.example.org", 443, false, RuleBlock, "*.example.org", true},
		{"block beats allow", func(o *config.OpenShellConfig) {
			o.Egress.Block, o.Egress.Allow = []string{"example.org"}, []string{"example.org"}
		}, Flags{}, "example.org", 443, false, RuleBlock, "example.org", true},
		{"apex is not a subdomain", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"*.example.org"} }, Flags{},
			"example.org", 443, true, RuleNetworkOpen, "", false},
		{"port outside the list", nil, Flags{}, "example.org", 22, false, RulePort, "22", false},
		{"port unchecked", nil, Flags{}, "example.org", 0, true, RuleNetworkOpen, "", false},
		{"user ports", func(o *config.OpenShellConfig) { o.Egress.Ports = []int{8443} }, Flags{}, "example.org", 443, false, RulePort, "443", false},
		{"allowlist hit", nil, Flags{Profile: "balanced"}, "example.org", 443, false, RuleNetworkAllowlist, "", true},
		{"allowlist pack entry", nil, Flags{Pack: "balanced"}, "pypi.org", 443, true, RuleAllow, "pypi.org", false},
		{"deny profile", nil, Flags{Profile: "strict"}, "pypi.org", 443, false, RuleNetworkDeny, "", false},
		{"admin block", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock, o.Egress.Allow = []string{"*.ngrok.io"}, []string{"a.ngrok.io"}
		}, Flags{}, "a.ngrok.io", 443, false, RuleAdminBlock, "*.ngrok.io", false},
		{"admin allow-only miss", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			"pypi.org", 443, false, RuleAdminAllowOnly, "", false},
		{"admin allow-only hit", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			"git.corp.example", 443, true, RuleAdminAllowOnly, "*.corp.example", false},
		{"feed inside allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.pastebin.com"} }, Flags{},
			"x.pastebin.com", 443, false, RuleFeed, "exfil:x.pastebin.com", true},
		{"unblock disabled", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			"webhook.site", 443, false, RuleFeed, "exfil:webhook.site", false},
		{"curated allow entry exempts from the feed", nil, Flags{Pack: "balanced"},
			"raw.githubusercontent.com", 443, true, RuleAllow, "raw.githubusercontent.com", false},
		{"nothing exempts from the feed when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{Pack: "balanced"},
			"raw.githubusercontent.com", 443, false, RuleFeed, "exfil:raw.githubusercontent.com", false},
		{"raised profile uses the curated allowlist", nil, Flags{Profile: "balanced"},
			"registry.npmjs.org", 443, true, RuleAllow, "registry.npmjs.org", false},
		{"admin floor uses the curated allowlist", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "balanced" }, Flags{},
			"pypi.org", 443, true, RuleAllow, "pypi.org", false},
		{"user allow-everything is ignored", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"*", "*.com"} }, Flags{Profile: "balanced"},
			"example.com", 443, false, RuleNetworkAllowlist, "", true},
		// The reported bypass: an admin balanced floor, no unblocking, and a
		// user allow-everything entry.
		{"floor with a user allow-everything entry", func(o *config.OpenShellConfig) {
			o.Egress.Allow, o.Admin.MinProfile, o.Admin.AllowUnblock = []string{"*"}, "balanced", boolPtr(false)
		}, Flags{}, "webhook.site", 443, false, RuleFeed, "exfil:webhook.site", false},
		{"ip literal", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"2001:db8::1"} }, Flags{},
			"[2001:db8::1]", 443, false, RuleBlock, "2001:db8::1", true},
		{"empty host", nil, Flags{}, "", 443, false, RuleInvalid, "", false},
		{"wildcard host", nil, Flags{}, "*.example.org", 443, false, RuleInvalid, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, _ := mustResolve(t, testConfig(tc.edit), tc.flags)
			got := eff.DecideEgress(tc.host, tc.port, feed)
			want := EgressDecision{Allowed: tc.allowed, Rule: tc.rule, Match: tc.match, Unblockable: tc.unblockable}
			if got != want {
				t.Fatalf("DecideEgress(%q, %d) = %+v, want %+v", tc.host, tc.port, got, want)
			}
		})
	}

	eff, _ := mustResolve(t, testConfig(nil), Flags{})
	if got := eff.DecideEgress("webhook.site", 443, nil); !got.Allowed {
		t.Fatalf("without a feed matcher the feed step is skipped: %+v", got)
	}
	var nilEff *Effective
	if got := nilEff.DecideEgress("example.org", 443, feed); got.Allowed {
		t.Fatal("a nil Effective must refuse egress")
	}
}

func TestMatchHost(t *testing.T) {
	for _, tc := range []struct {
		glob, host string
		want       bool
	}{
		{"*", "anything.example", true},
		{"example.com", "example.com", true},
		{"example.com", "EXAMPLE.com.", true},
		{"example.com", "www.example.com", false},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "badexample.com", false},
		{"[2001:db8::1]", "2001:db8::1", true},
		{"203.0.113.7", "203.0.113.7", true},
		{"", "example.com", false},
		{"example.com", "", false},
	} {
		if got := MatchHost(tc.glob, tc.host); got != tc.want {
			t.Errorf("MatchHost(%q, %q) = %v, want %v", tc.glob, tc.host, got, tc.want)
		}
	}
	if !MatchAnyHost([]string{"a.example", "*.b.example"}, "x.b.example") || MatchAnyHost(nil, "x") {
		t.Fatal("MatchAnyHost")
	}
}
