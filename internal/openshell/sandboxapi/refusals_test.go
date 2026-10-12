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

package sandboxapi_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

var updateRefusals = flag.Bool("update-refusals", false, "rewrite testdata/refusals.golden")

// TestRefusalMessagesGolden pins every refusal text (plan §7.1). Rewrite
// with: go test ./internal/openshell/sandboxapi -run RefusalMessagesGolden -update-refusals
func TestRefusalMessagesGolden(t *testing.T) {
	cases := []struct{ name, text string }{
		{"HostRunRefused", sandboxapi.HostRunRefused("claudecode", "contractors", "/home/alice/src/api", "it-security@example.com")},
		{"HostRunRefused codex, no profile, no contact", sandboxapi.HostRunRefused("codex", "", "/home/alice/src/api", "")},
		{"HostRunRefused relative project", sandboxapi.HostRunRefused("cursor", "contractors", "src/api", "it-security@example.com")},
		{"HostRunRefused quoted project", sandboxapi.HostRunRefused("copilot", "contractors", "/home/al'ice/my api/", "it-security@example.com")},
		{"HostRunRefused escape in project", sandboxapi.HostRunRefused("claudecode", "contractors", "/home/alice/\x1b]0;x\x07", "it-security@example.com")},
		{"HostRunRefused forged profile line", sandboxapi.HostRunRefused("claudecode", "contractors\nAllowed: yes", "/srv", "it\r\nsecurity")},
		{"HostRunRefusedOn cli", sandboxapi.HostRunRefusedOn("claudecode", "cli", "contractors", "/home/alice/src/api", "it-security@example.com")},
		{"HostRunRefusedOn extension", sandboxapi.HostRunRefusedOn("copilot", "extension", "contractors", "/home/alice/src/api", "it-security@example.com")},
		{"HostRunRefusedOn desktop, relative project", sandboxapi.HostRunRefusedOn("cursor", "desktop", "", "src/api", "")},
		{"HostRunRefusedOn extension, no product", sandboxapi.HostRunRefusedOn("opencode", "extension", "contractors", "/srv", "it-security@example.com")},
		{"HostRunUnavailable", sandboxapi.HostRunUnavailable("claudecode", "OpenShell is not installed", "prerequisite_missing", "it-security@example.com")},
		{"HostRunUnavailable no reason", sandboxapi.HostRunUnavailable("copilot", "", "", "")},
		{"HostRunUnavailable kvm group", sandboxapi.HostRunUnavailable("claudecode", "your account isn't in the kvm group that can use /dev/kvm", "no_kvm_group", "it-security@example.com")},
		{"HostRunUnavailable reason with a period, bad code", sandboxapi.HostRunUnavailable("codex", "this computer has no KVM.", "No KVM!", "")},
		{"ProvisionalRefusal refused", sandboxapi.ProvisionalRefusal(sandboxapi.HostRunRefused("claudecode", "offline-floor", "/home/bob/src/api", "it-security@example.com"))},
		{"ProvisionalRefusal unavailable", sandboxapi.ProvisionalRefusal(sandboxapi.HostRunUnavailable("claudecode", "your account's groups couldn't be looked up", "account_lookup_failed", "it-security@example.com"))},
		{"AccessRefused", sandboxapi.AccessRefused("egress_allow_only", "api.example.net", "contractors", "brave-otter", "it-security@example.com")},
		{"AccessRefusedWhy allow list (GAP-0572)", sandboxapi.AccessRefusedWhy("api.example.net is not on your organization's list of allowed destinations",
			"egress_allow_only", "api.example.net", "contractors", "brave-otter", "it-security@example.com")},
		{"AccessRefused egress_block, no profile", sandboxapi.AccessRefused("egress_block", "pastebin.com", "", "", "")},
		{"AccessRefused unknown rule", sandboxapi.AccessRefused("future_rule", "", "contractors", "brave-otter", "it-security@example.com")},
		{"AccessRefusedWhy session only", sandboxapi.AccessRefusedWhy(sandboxapi.AdminMessage+": your profile lets you approve access for this session only, not for future sandboxes",
			"user_approvals", "api.example.net", "contractors", "brave-otter", "it-security@example.com")},
		{"AccessRefusedWhy says it already", sandboxapi.AccessRefusedWhy("your profile doesn't let you approve sandbox access; you can't approve this",
			"user_approvals", "host.openshell.internal:5432", "tt-none", "un04n", "")},
		{"AccessRefusedWhy blocklist", sandboxapi.AccessRefusedWhy(sandboxapi.AdminMessage+": pastebin.com matches pastebin.com on your organization's blocklist",
			"egress_block", "pastebin.com", "devs", "pm28a", "it-security@example.com")},
		{"ForeignStopped", sandboxapi.ForeignStopped("build-1")},
		{"ForeignRemoved", sandboxapi.ForeignRemoved("build-1")},
		{"ForeignRemoving", sandboxapi.ForeignRemoving("build-1")},
		{"ForeignNotRemoved", sandboxapi.ForeignNotRemoved("build-1", "Provisioning")},
		{"ForeignAlerted", sandboxapi.ForeignAlerted("build-1")},
		{"SettingsDrift", sandboxapi.SettingsDrift("compute driver")},
		{"PolicyUnloadable", sandboxapi.PolicyUnloadable()},
		{"ProfileStop", sandboxapi.ProfileStop("mounts", "claudecode", "")},
		{"ProfileStop command", sandboxapi.ProfileStop("mounts", "codex", "")},
		{"AccountBusy", sandboxapi.AccountBusy()},
		{"DriverUnavailable", sandboxapi.DriverUnavailable("KVM not available on this computer", "it-security@example.com")},
		{"DriverUnavailable no reason, no contact", sandboxapi.DriverUnavailable("", "")},
		{"DockerUnavailable socket error (GAP-0625)", sandboxapi.ManagedRefusal(sandboxapi.DockerUnavailable("permission denied while trying to connect to the docker API at unix:///var/run/docker.sock",
			"it-security@example.com"), "contractors", "", "other@example.com")},
		{"HarnessNotAllowed", sandboxapi.HarnessNotAllowed("amp", "engineering", "it-security@example.com")},
		{"HarnessNotAllowed no profile, no contact", sandboxapi.HarnessNotAllowed("cursor", "", "")},
		{"HarnessNotEnabled", sandboxapi.HarnessNotEnabled("opencode", "engineering", "it-security@example.com")},
		{"HarnessNotEnabled bad connector", sandboxapi.HarnessNotEnabled("Open\x1bCode", "", "")},
		{"ManagedRefusal gateway sentence", sandboxapi.ManagedRefusal("Your organization doesn't allow sandboxes for your account.", "engineering", "", "it-security@example.com")},
		{"ManagedRefusal open pack (GAP-0573)", sandboxapi.ManagedRefusal("pack (your profile contractors requires the contractors sandbox pack or a stricter one; the open pack is looser in network.mode)",
			"contractors", "", "it-security@example.com")},
		{"ManagedRefusal admin prefix, quote", sandboxapi.ManagedRefusal(sandboxapi.AdminMessage, "", "reason sandbox_unavailable", "")},
		{"ManagedRefusal own contact kept", sandboxapi.ManagedRefusal(sandboxapi.DriverUnavailable("KVM not available on this computer", "it-security@example.com"), "contractors", "", "other@example.com")},
		{"ManagedRefusal forged line", sandboxapi.ManagedRefusal("This agent isn't allowed\nAllowed: yes", "contractors\nx", "", "it\r\nsecurity")},
	}
	var b strings.Builder
	for _, c := range cases {
		b.WriteString("== " + c.name + "\n" + c.text + "\n")
	}
	got := b.String()
	golden := filepath.Join("testdata", "refusals.golden")
	if *updateRefusals {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s (run with -update-refusals to create it): %v", golden, err)
	}
	if got != string(want) {
		t.Fatalf("refusal texts drifted from %s (rerun with -update-refusals after review):\n%s", golden, got)
	}
	for _, c := range cases {
		if strings.ContainsAny(c.text, "\x1b\x07\r") {
			t.Errorf("%s carries a control character: %q", c.name, c.text)
		}
	}
}

func TestProfileStopOffersAPermittedNextStep(t *testing.T) {
	for _, tc := range []struct{ field, access, want, absent string }{
		{"sandboxes", "help@example.invalid", "Request access: help@example.invalid.", "Start it again"},
		{"this agent in a sandbox", "", "Request access: your IT help desk.", "Start it again"},
		{"sandboxes", "help\x1b[2J@example.invalid\n", "Request access: help", "\x1b"},
		{"host ports", "help@example.invalid", "Start it again: defenseclaw sandbox run claude", "Request access"},
	} {
		t.Run(tc.field+tc.access, func(t *testing.T) {
			text := sandboxapi.ProfileStop(tc.field, "claudecode", tc.access)
			if !strings.Contains(text, tc.want) || strings.Contains(text, tc.absent) {
				t.Fatalf("stop notice = %q", text)
			}
		})
	}
}

func TestEgressRefusalUsesTheSameSentence(t *testing.T) {
	for _, c := range []struct{ rule, why string }{
		{"egress_allow_only", "api.example.net is not on your organization's list of allowed destinations"},
		{"egress_block", "api.example.net matches example.net on your organization's blocklist"},
	} {
		activity := sandboxapi.AccessRefused(c.rule, "api.example.net", "contractors", "brave-otter", "help@example.com")
		unblock := sandboxapi.AccessRefusedWhy(c.why, c.rule, "api.example.net", "contractors", "brave-otter", "help@example.com")
		if unblock != activity {
			t.Errorf("%s: unblock = %q, activity = %q", c.rule, unblock, activity)
		}
	}
}

func TestManagedPackRefusalIsComplete(t *testing.T) {
	text := sandboxapi.ManagedRefusal("pack (your profile contractors requires the contractors sandbox pack or a stricter one; the open pack is looser in network.mode)",
		"contractors", "", "help@example.com")
	for _, want := range []string{
		"your profile contractors requires the contractors sandbox pack or a stricter one; the open pack is looser in network.mode",
		"You can't approve this.", "Request access: help@example.com.", "Quote: profile contractors, rule required_pack, pack open.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("pack refusal lacks %q: %q", want, text)
		}
	}
	if strings.Contains(text, ": pack (") {
		t.Errorf("pack refusal is a fragment: %q", text)
	}
}

func TestDockerRefusalKeepsOneContactAndNoRuntimeDetails(t *testing.T) {
	for _, raw := range []string{
		"permission denied while trying to connect to the docker API at unix:///var/run/docker.sock",
		"Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
		"container runtime diagnostic marker",
	} {
		text := sandboxapi.ManagedRefusal(sandboxapi.DockerUnavailable(raw, "help@example.com"), "contractors", "", "other@example.com")
		if strings.Count(text, "help@example.com") != 1 || strings.Contains(text, "other@example.com") || strings.Contains(text, raw) || strings.Contains(text, "docker.sock") {
			t.Errorf("Docker refusal repeats the contact or exposes runtime details: %q", text)
		}
		if !strings.Contains(text, "Start Docker Desktop") {
			t.Errorf("Docker refusal lacks the next step: %q", text)
		}
	}
}

// TestRefusalPolicyMessagesShape pins the rule every policy refusal follows:
// it starts with AdminMessage and ends with the request-access contact.
func TestRefusalPolicyMessagesShape(t *testing.T) {
	prefix := "B" + sandboxapi.AdminMessage[1:] + ": "
	for name, text := range map[string]string{
		"HostRunRefused":     sandboxapi.HostRunRefused("claudecode", "contractors", "/p", "help@example.com"),
		"HostRunUnavailable": sandboxapi.HostRunUnavailable("claudecode", "x", "no_kvm", "help@example.com"),
		"HostRunRefusedOn":   sandboxapi.HostRunRefusedOn("cursor", "desktop", "contractors", "/p", "help@example.com"),
		"ProvisionalRefusal": sandboxapi.ProvisionalRefusal(sandboxapi.HostRunUnavailable("claudecode", "x", "no_kvm", "help@example.com")),
		"DriverUnavailable":  sandboxapi.DriverUnavailable("KVM not available on this computer", "help@example.com"),

		"AccessRefused":     sandboxapi.AccessRefused("egress_allow_only", "h", "contractors", "s", "help@example.com"),
		"HarnessNotAllowed": sandboxapi.HarnessNotAllowed("amp", "engineering", "help@example.com"),
		"HarnessNotEnabled": sandboxapi.HarnessNotEnabled("opencode", "engineering", "help@example.com"),
		"ManagedRefusal":    sandboxapi.ManagedRefusal("Your organization doesn't allow sandboxes for your account.", "p", "", "help@example.com"),
	} {
		if !strings.HasPrefix(text, prefix) {
			t.Errorf("%s does not start with AdminMessage: %q", name, text)
		}
		if !strings.Contains(text[strings.LastIndex(text, "\n")+1:], "help@example.com") {
			t.Errorf("%s does not end with the request-access contact: %q", name, text)
		}
	}
}

// The Docker prerequisite of a MicroVM run is a long reason; it is quoted
// whole, never cut inside the sentence (GAP-0555).
func TestHostRunUnavailableKeepsALongReasonWhole(t *testing.T) {
	why := "MicroVM sandboxes start from an agent image built in Docker for your account, and your account isn't in the docker group that can use Docker"
	got := sandboxapi.HostRunUnavailable("claudecode", why, "no_docker_group", "help@example.com")
	if !strings.Contains(got, "("+why+")") || strings.Contains(got, "…") {
		t.Fatalf("reason cut or reworded: %q", got)
	}
	// DockerUnavailable is not checked here: its why is Docker's raw answer,
	// which the refusal maps to a plain explanation (GAP-0625).
	long := sandboxapi.HostRunUnavailable("claudecode", strings.Repeat("x ", 400), "no_kvm", "help@example.com")
	if !strings.Contains(long, "…") || len(long) > 1024 {
		t.Fatalf("a reason past the bound is clipped: %d bytes", len(long))
	}
}

// A surface tells a complete managed refusal from a bare reason, and finds
// its request-access line (GAP-0508, GAP-0502).
func TestPolicyRefusalAndQuoteLine(t *testing.T) {
	text := sandboxapi.AccessRefused("allow_unblock", "example.org", "tt-2", "pm28a", "help@example.com")
	if !sandboxapi.IsPolicyRefusal(text) || sandboxapi.IsPolicyRefusal(sandboxapi.AdminMessage+": egress.unblock") {
		t.Fatalf("IsPolicyRefusal(%q) wrong", text)
	}
	if got := sandboxapi.QuoteLine(text); got != "Request access: help@example.com. Quote: profile tt-2, rule allow_unblock, host example.org, sandbox pm28a." {
		t.Fatalf("QuoteLine = %q", got)
	}
	if got := sandboxapi.QuoteLine("no quote here"); got != "" {
		t.Fatalf("QuoteLine of a bare reason = %q", got)
	}
}

// TestRefusalHarnessNamesMatchHarnessSpecs pins the message table to the
// harness registry: every harness reads with its display name and the name
// `sandbox run` takes for it.
func TestRefusalHarnessNamesMatchHarnessSpecs(t *testing.T) {
	for _, name := range harness.Names() {
		spec, ok := harness.Get(name)
		if !ok {
			t.Fatalf("harness %s not found", name)
		}
		text := sandboxapi.HostRunRefused(name, "", "/p", "")
		if !strings.Contains(text, ": "+spec.DisplayName+" must run in a sandbox") {
			t.Errorf("%s: display name %q missing: %q", name, spec.DisplayName, text)
		}
		arg := sandboxcli.HarnessArg(spec)
		if !strings.Contains(text, "defenseclaw sandbox run "+arg+"\n") ||
			!strings.Contains(text, "defenseclaw sandbox enable "+arg+"\n") {
			t.Errorf("%s: harness argument %q missing: %q", name, arg, text)
		}
	}
}
