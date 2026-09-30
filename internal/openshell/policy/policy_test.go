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

package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	"gopkg.in/yaml.v3"
)

func baseInput(profile Profile, harness string) Input {
	return Input{
		Profile:     profile,
		Harness:     harness,
		Workdir:     "/work/myapp",
		WorkdirMode: WorkdirMount,
		RunAsUser:   "1000",
		RunAsGroup:  "1000",
		IngressPort: 18971,
		EgressPort:  18972,
		APIPort:     DefaultAPIPort,
		GatewayPort: DefaultGatewayPort,
	}
}

// goldenCases is the profile x harness matrix plus the copy-mode, context
// mount and extra-rule shapes.
func goldenCases() map[string]Input {
	cases := map[string]Input{}
	for _, profile := range []Profile{ProfileOpen, ProfileBalanced, ProfileStrict} {
		for _, harness := range []string{"claudecode", "codex"} {
			in := baseInput(profile, harness)
			if harness == "claudecode" {
				in.HarnessReadOnly = []string{"/opt/defenseclaw-harness/claudecode"}
			}
			cases[string(profile)+"-"+harness] = in
		}
	}
	copyMode := baseInput(ProfileOpen, "codex")
	copyMode.WorkdirMode = WorkdirCopy
	copyMode.Workdir = "/sandbox/work/myapp"
	copyMode.RunAsUser, copyMode.RunAsGroup = "1001", "1001"
	cases["open-codex-copy"] = copyMode

	context := baseInput(ProfileBalanced, "claudecode")
	context.Mounts = []Mount{
		{Target: "/work/myapp/.git/hooks", ReadOnly: true},
		{Target: "/work/myapp/.env", ReadOnly: true},
		{Target: "/context/lib", ReadOnly: true},
		{Target: "/context/scratch", ReadOnly: false},
	}
	cases["balanced-claudecode-context"] = context

	hostPort := baseInput(ProfileStrict, "codex")
	hostPort.HostPorts = []int{5432}
	hostPort.ExtraRules = map[string]v1.NetworkPolicyRule{
		"host_port_5432": {
			Endpoints: []v1.PolicyNetworkEndpoint{{Host: "host.openshell.internal", Port: 5432, Protocol: "tcp", TLS: v1.NetworkTLSModeSkip}},
			Binaries:  []v1.PolicyNetworkBinary{{Path: "/**"}},
		},
		"docs_python": {
			Endpoints: []v1.PolicyNetworkEndpoint{{Host: "docs.python.org", Port: 443, Protocol: "rest", Access: v1.NetworkAccessPresetReadOnly, Enforcement: v1.NetworkEnforcementModeEnforce}},
			Binaries:  []v1.PolicyNetworkBinary{{Path: "/usr/bin/curl"}},
		},
	}
	cases["strict-codex-extra-rules"] = hostPort
	return cases
}

// TestRenderGolden pins every rendered shape byte for byte, its strict
// round trip, and (for the built-in profiles) that it only uses keys
// OpenShell accepted.
func TestRenderGolden(t *testing.T) {
	update := os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1"
	for name, in := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			p := mustRender(t, in)
			out, err := MarshalYAML(p)
			if err != nil {
				t.Fatalf("MarshalYAML: %v", err)
			}
			golden := filepath.Join("testdata", name+".yaml")
			if update {
				if err := os.WriteFile(golden, out, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
			}
			if !bytes.Equal(want, out) {
				t.Fatalf("%s drifted:\n%s", golden, out)
			}
			// The YAML is unknown-field free: strict parsing restores the
			// exact typed policy.
			back, err := ParseYAML(out)
			if err != nil {
				t.Fatalf("ParseYAML: %v", err)
			}
			if !reflect.DeepEqual(back, p) {
				t.Fatalf("round trip changed the policy:\n got %#v\nwant %#v", back, p)
			}
			if len(in.ExtraRules) == 0 {
				assertAcceptedKeys(t, out)
			}
		})
	}
}

// acceptedKeys are the policy-file keys OpenShell 0.1.1 loaded in the
// harness spike (hs-policy-*.yaml and spike4.yaml). The built-in profiles may
// only emit these.
var acceptedKeys = map[string]bool{
	"version": true, "filesystem_policy": true, "landlock": true, "process": true, "network_policies": true,
	"include_workdir": true, "read_only": true, "read_write": true, "compatibility": true,
	"run_as_user": true, "run_as_group": true, "endpoints": true, "binaries": true,
	"host": true, "port": true, "protocol": true, "tls": true, "access": true, "enforcement": true, "path": true,
}

// assertAcceptedKeys fails on any key of the policy document (other than
// rule names) that OpenShell was never seen to accept.
func assertAcceptedKeys(t *testing.T, out []byte) {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal(out, &node); err != nil {
		t.Fatal(err)
	}
	var walk func(node *yaml.Node, underRules bool)
	walk = func(node *yaml.Node, underRules bool) {
		switch node.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, child := range node.Content {
				walk(child, false)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				key := node.Content[i].Value
				if !underRules && !acceptedKeys[key] {
					t.Errorf("key %q was never validated against OpenShell", key)
				}
				walk(node.Content[i+1], key == "network_policies")
			}
		}
	}
	walk(&node, false)
}

// TestRenderIngressRule pins the ingress rule of a sandbox without an
// ingress provider (token_delivery: env): in every profile, plain HTTP to
// the ingress port only, for every binary, in keys OpenShell accepted.
func TestRenderIngressRule(t *testing.T) {
	for _, profile := range []Profile{ProfileOpen, ProfileBalanced, ProfileStrict} {
		in := baseInput(profile, "claudecode")
		if _, ok := mustRender(t, in).NetworkPolicies[IngressRuleName]; ok {
			t.Fatalf("%s: ingress rule without IngressRule", profile)
		}
		in.IngressRule = true
		p := mustRender(t, in)
		rule, ok := p.NetworkPolicies[IngressRuleName]
		if !ok || rule.Name != IngressRuleName || len(rule.Endpoints) != 1 || len(rule.Binaries) != 1 || rule.Binaries[0].Path != AnyBinary {
			t.Fatalf("%s: ingress rule = %#v", profile, rule)
		}
		ep := rule.Endpoints[0]
		if ep.Host != EgressHost || ep.Port != 18971 || len(ep.Ports) != 0 || ep.Protocol != "rest" ||
			ep.Access != v1.NetworkAccessPresetFull || ep.Enforcement != v1.NetworkEnforcementModeEnforce || ep.TLS != v1.NetworkTLSModeUnspecified {
			t.Fatalf("%s: ingress endpoint = %#v", profile, ep)
		}
		out, err := MarshalYAML(p)
		if err != nil {
			t.Fatal(err)
		}
		assertAcceptedKeys(t, out)
		if back, err := ParseYAML(out); err != nil || !reflect.DeepEqual(back.NetworkPolicies[IngressRuleName], rule) {
			t.Fatalf("%s: the ingress rule did not survive YAML: %v", profile, err)
		}
	}
	// An extra rule may not take the ingress rule's name.
	in := baseInput(ProfileOpen, "codex")
	in.ExtraRules = map[string]v1.NetworkPolicyRule{IngressRuleName: anyRule("example.org", 443)}
	if _, err := Render(in); err == nil {
		t.Fatal("an extra rule took the ingress rule's name")
	}
}

// TestRenderFilesystem covers what the goldens do not pin: nested harness
// roots outside the base read-only set collapse into their parent, and mount
// targets under the workdir are enforced by their mount alone.
func TestRenderFilesystem(t *testing.T) {
	outside := baseInput(ProfileOpen, "claudecode")
	outside.HarnessReadOnly = []string{"/nix/store/claude", "/nix/store/claude/bin"}
	if got := mustRender(t, outside).Filesystem.ReadOnly; !slices.Contains(got, "/nix/store/claude") || slices.Contains(got, "/nix/store/claude/bin") {
		t.Errorf("harness roots outside the base = %v", got)
	}
	fs := mustRender(t, goldenCases()["balanced-claudecode-context"]).Filesystem
	for _, inside := range []string{"/work/myapp/.git/hooks", "/work/myapp/.env"} {
		if slices.Contains(fs.ReadOnly, inside) || slices.Contains(fs.ReadWrite, inside) {
			t.Errorf("%s is under the workdir and must be enforced by its mount only", inside)
		}
	}
}

func TestRenderRejectsUnsafeInput(t *testing.T) {
	mutate := func(fn func(*Input)) Input {
		in := baseInput(ProfileOpen, "codex")
		fn(&in)
		return in
	}
	withRule := func(fn func(*v1.NetworkPolicyRule)) Input {
		r := anyRule("example.org", 443)
		fn(&r)
		return mutate(func(in *Input) { in.ExtraRules = map[string]v1.NetworkPolicyRule{"x": r} })
	}
	cases := map[string]Input{
		"unknown-profile":    mutate(func(in *Input) { in.Profile = "yolo" }),
		"bad-harness":        mutate(func(in *Input) { in.Harness = "Claude Code" }),
		"no-mode":            mutate(func(in *Input) { in.WorkdirMode = "" }),
		"relative-workdir":   mutate(func(in *Input) { in.Workdir = "work/myapp" }),
		"unclean-workdir":    mutate(func(in *Input) { in.Workdir = "/work/../etc" }),
		"root-workdir":       mutate(func(in *Input) { in.Workdir = "/" }),
		"system-workdir":     mutate(func(in *Input) { in.Workdir = "/usr/local/src" }),
		"mount-outside-work": mutate(func(in *Input) { in.Workdir = "/srv/myapp" }),
		"workdir-is-home":    mutate(func(in *Input) { in.WorkdirMode = WorkdirCopy; in.Workdir = "/sandbox" }),
		"root-user":          mutate(func(in *Input) { in.RunAsUser = "0" }),
		"root-group-name":    mutate(func(in *Input) { in.RunAsGroup = "root" }),
		"named-user-mount":   mutate(func(in *Input) { in.RunAsUser = "sandbox" }),
		"named-user-copy": mutate(func(in *Input) {
			in.WorkdirMode, in.Workdir, in.RunAsUser, in.RunAsGroup = WorkdirCopy, "/sandbox/work/myapp", "sandbox", "sandbox"
		}),
		"shell-in-user":          mutate(func(in *Input) { in.RunAsUser = "1000;rm" }),
		"missing-egress":         mutate(func(in *Input) { in.EgressPort = 0 }),
		"port-collision":         mutate(func(in *Input) { in.EgressPort = in.IngressPort }),
		"missing-ingress":        mutate(func(in *Input) { in.IngressPort = 0 }),
		"mount-over-etc":         mutate(func(in *Input) { in.Mounts = []Mount{{Target: "/etc/ssh", ReadOnly: true}} }),
		"mount-parent-of-system": mutate(func(in *Input) { in.Mounts = []Mount{{Target: "/", ReadOnly: true}} }),
		"mount-parent-of-work":   mutate(func(in *Input) { in.Mounts = []Mount{{Target: "/work", ReadOnly: false}} }),
		"harness-root-slash":     mutate(func(in *Input) { in.HarnessReadOnly = []string{"/"} }),
		"reserved-rule": mutate(func(in *Input) {
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"defenseclaw_x": anyRule("example.org", 443)}
		}),
		"provider-rule": mutate(func(in *Input) {
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"_provider_x": anyRule("example.org", 443)}
		}),
		"rule-to-ingress": mutate(func(in *Input) {
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"x": anyRule("host.openshell.internal", 18971)}
		}),
		"rule-no-binaries":   withRule(func(r *v1.NetworkPolicyRule) { r.Binaries = nil }),
		"rule-terminate-tls": withRule(func(r *v1.NetworkPolicyRule) { r.Endpoints[0].TLS = v1.NetworkTLSModeTerminate }),
		"rule-l7-on-tcp":     withRule(func(r *v1.NetworkPolicyRule) { r.Endpoints[0].Access = v1.NetworkAccessPresetFull }),
		"rule-credential-binding": withRule(func(r *v1.NetworkPolicyRule) {
			r.Endpoints[0].CredentialBinding = &types.NetworkCredentialBinding{Provider: "p"}
		}),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Render(in); err == nil {
				t.Fatal("unsafe input rendered")
			}
		})
	}
}

// TestRenderKeepsExtraRulesOffReservedEndpoints covers every spelling of a
// DefenseClaw or OpenShell listener an extra rule could use: other ports,
// the Ports list, host case, wildcards, loopback aliases, IP literals and
// allowed_ips ranges.
func TestRenderKeepsExtraRulesOffReservedEndpoints(t *testing.T) {
	endpoint := func(ep v1.PolicyNetworkEndpoint) map[string]v1.NetworkPolicyRule {
		if ep.Protocol == "" {
			ep.Protocol = "tcp"
		}
		return map[string]v1.NetworkPolicyRule{"x": {Endpoints: []v1.PolicyNetworkEndpoint{ep}, Binaries: []v1.PolicyNetworkBinary{{Path: "/**"}}}}
	}
	render := func(ep v1.PolicyNetworkEndpoint, hostPorts []int) error {
		in := baseInput(ProfileOpen, "codex")
		in.HostPorts = hostPorts
		in.ExtraRules = endpoint(ep)
		_, err := Render(in)
		return err
	}
	refused := map[string]struct {
		ep        v1.PolicyNetworkEndpoint
		hostPorts []int
		want      string
	}{
		"ingress-in-ports-list":  {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Ports: []uint32{18971}}, nil, "hook ingress"},
		"egress-in-ports-list":   {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Ports: []uint32{5432, 18972}}, []int{5432}, "egress proxy"},
		"upper-case-ingress":     {v1.PolicyNetworkEndpoint{Host: "HOST.OPENSHELL.INTERNAL", Port: 18971}, nil, "hook ingress"},
		"mixed-case-api":         {v1.PolicyNetworkEndpoint{Host: "Host.OpenShell.Internal", Port: 18970}, nil, "DefenseClaw API"},
		"main-api":               {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Port: 18970}, nil, "DefenseClaw API"},
		"openshell-gateway":      {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Port: 17670}, nil, "OpenShell gateway"},
		"unconsented-host-port":  {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Port: 5433}, []int{5432}, "not a consented host port"},
		"wildcard-openshell":     {v1.PolicyNetworkEndpoint{Host: "*.openshell.internal", Port: 18972}, nil, "could match host.openshell.internal"},
		"double-wildcard-tld":    {v1.PolicyNetworkEndpoint{Host: "**.internal", Port: 443}, nil, "could match host.openshell.internal"},
		"wildcard-openshell-sub": {v1.PolicyNetworkEndpoint{Host: "*.x.openshell.internal", Port: 443}, nil, "could match host.openshell.internal"},
		"wildcard-docker-host":   {v1.PolicyNetworkEndpoint{Host: "*.docker.internal", Port: 443}, nil, "loopback name"},
		"wildcard-localhost":     {v1.PolicyNetworkEndpoint{Host: "*.localhost", Port: 443}, nil, "loopback name"},
		"openshell-name":         {v1.PolicyNetworkEndpoint{Host: "gateway.openshell.internal", Port: 443}, nil, "reserved by OpenShell"},
		"localhost":              {v1.PolicyNetworkEndpoint{Host: "localhost", Port: 18970}, nil, "loopback name"},
		"localhost-subdomain":    {v1.PolicyNetworkEndpoint{Host: "api.localhost", Port: 80}, nil, "loopback name"},
		"docker-desktop-host":    {v1.PolicyNetworkEndpoint{Host: "host.docker.internal", Port: 18970}, nil, "loopback name"},
		"loopback-literal":       {v1.PolicyNetworkEndpoint{Host: "127.0.0.1", Port: 18970}, nil, "loopback"},
		"short-loopback":         {v1.PolicyNetworkEndpoint{Host: "127.1", Port: 18970}, nil, "canonical"},
		"decimal-loopback":       {v1.PolicyNetworkEndpoint{Host: "2130706433", Port: 18970}, nil, "canonical"},
		"hex-loopback":           {v1.PolicyNetworkEndpoint{Host: "0x7f000001", Port: 18970}, nil, "canonical"},
		"zero-padded-loopback":   {v1.PolicyNetworkEndpoint{Host: "127.000.000.001", Port: 18970}, nil, "canonical"},
		"metadata-literal":       {v1.PolicyNetworkEndpoint{Host: "169.254.169.254", Port: 80}, nil, "link-local"},
		"synthetic-literal":      {v1.PolicyNetworkEndpoint{Host: "198.18.0.2", Port: 18971}, nil, "OpenShell synthetic"},
		"cgnat-literal":          {v1.PolicyNetworkEndpoint{Host: "100.100.100.200", Port: 80}, nil, "CGNAT"},
		"wildcard-ip":            {v1.PolicyNetworkEndpoint{Host: "*.0.0.1", Port: 80}, nil, "canonical"},
		"allowed-loopback":       {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 5432, AllowedIPs: []string{"127.0.0.0/8"}}, nil, "loopback"},
		"allowed-loopback-addr":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 5432, AllowedIPs: []string{"127.0.0.2"}}, nil, "loopback"},
		"allowed-metadata":       {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"169.254.169.254/32"}}, nil, "link-local"},
		"allowed-cgnat":          {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"100.64.0.0/10"}}, nil, "CGNAT"},
		"allowed-everything":     {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"0.0.0.0/0"}}, nil, "overlaps"},
		"allowed-synthetic":      {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"198.18.0.0/16"}}, nil, "OpenShell synthetic"},
		"allowed-v6-loopback":    {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"::1/128"}}, nil, "loopback"},
		"allowed-v4-mapped":      {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"::ffff:127.0.0.1"}}, nil, "loopback"},
		"allowed-v4-mapped-all":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"::ffff:0:0/96"}}, nil, "overlaps"},
		"allowed-v6-link-local":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"fe80::/10"}}, nil, "link-local"},
		"allowed-v6-everything":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"::/0"}}, nil, "overlaps"},
		"allowed-not-canonical":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"10.0.0.1/8"}}, nil, "canonical CIDR"},
		"allowed-garbage":        {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"db.internal"}}, nil, "not an IP"},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			if err := render(tc.ep, tc.hostPorts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}

	// Consented host ports themselves may not name a reserved listener.
	for _, port := range []int{18971, 18972, 18970, 17670, 70000, 0} {
		in := baseInput(ProfileOpen, "codex")
		in.HostPorts = []int{port}
		if _, err := Render(in); err == nil {
			t.Errorf("reserved or invalid host port %d consented", port)
		}
	}
	// Custom API and gateway ports move the reservation with them.
	moved := baseInput(ProfileOpen, "codex")
	moved.APIPort, moved.GatewayPort = 28970, 27670
	moved.HostPorts = []int{18970, 17670}
	moved.ExtraRules = endpoint(v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Ports: []uint32{18970, 17670}})
	if _, err := Render(moved); err != nil {
		t.Fatalf("ports freed by a custom API and gateway port: %v", err)
	}
	moved.HostPorts = []int{28970}
	moved.ExtraRules = nil
	if _, err := Render(moved); err == nil || !strings.Contains(err.Error(), "DefenseClaw API") {
		t.Fatalf("custom API port consented: %v", err)
	}

	accepted := map[string]struct {
		ep        v1.PolicyNetworkEndpoint
		hostPorts []int
	}{
		"consented-host-port":  {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Port: 5432}, []int{5432}},
		"consented-port-list":  {v1.PolicyNetworkEndpoint{Host: "HOST.openshell.internal", Ports: []uint32{5432, 8080}}, []int{8080, 5432}},
		"public-literal":       {v1.PolicyNetworkEndpoint{Host: "93.184.216.34", Port: 443}, nil},
		"public-wildcard":      {v1.PolicyNetworkEndpoint{Host: "**.example.org", Port: 443}, nil},
		"hex-looking-name":     {v1.PolicyNetworkEndpoint{Host: "0xproject.example.org", Port: 443}, nil},
		"lan-allowed-ips":      {v1.PolicyNetworkEndpoint{Host: "db.lan.example.org", Port: 5432, AllowedIPs: []string{"10.0.0.0/24", "192.168.1.20"}}, nil},
		"public-v6-allowed-ip": {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 5432, AllowedIPs: []string{"2001:db8::/32"}}, nil},
	}
	for name, tc := range accepted {
		if err := render(tc.ep, tc.hostPorts); err != nil {
			t.Errorf("%s: Render: %v", name, err)
		}
	}
}

func anyRule(host string, port uint32) v1.NetworkPolicyRule {
	return v1.NetworkPolicyRule{
		Endpoints: []v1.PolicyNetworkEndpoint{{Host: host, Port: port, Protocol: "tcp"}},
		Binaries:  []v1.PolicyNetworkBinary{{Path: "/**"}},
	}
}

func TestMarshalYAMLRefusesUnrepresentableFields(t *testing.T) {
	p := mustRender(t, baseInput(ProfileStrict, "codex"))
	p.NetworkPolicies["x"] = v1.NetworkPolicyRule{
		Name:      "x",
		Endpoints: []v1.PolicyNetworkEndpoint{{Host: "example.org", Port: 443, Protocol: "rest", AllowEncodedSlash: true}},
		Binaries:  []v1.PolicyNetworkBinary{{Path: "/**"}},
	}
	if _, err := MarshalYAML(p); err == nil || !strings.Contains(err.Error(), "does not carry") {
		t.Fatalf("MarshalYAML error = %v", err)
	}
}

func TestParseYAMLIsStrict(t *testing.T) {
	good, err := MarshalYAML(mustRender(t, baseInput(ProfileOpen, "codex")))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"unknown-top-key":      string(good) + "extra_key: 1\n",
		"unknown-endpoint-key": strings.Replace(string(good), "tls: skip", "tls: skip\n                bogus: true", 1),
		"unknown-tls":          strings.Replace(string(good), "tls: skip", "tls: terminate", 1),
		"second-document":      string(good) + "---\nversion: 1\n",
		"root-user":            strings.Replace(string(good), `run_as_user: "1000"`, `run_as_user: "0"`, 1),
		"best-effort-landlock": strings.Replace(string(good), "hard_requirement", "best_effort", 1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if doc == string(good) {
				t.Fatal("mutation did not apply")
			}
			if _, err := ParseYAML([]byte(doc)); err == nil {
				t.Fatal("invalid document parsed")
			}
		})
	}
}

// TestParseYAMLAcceptsSpikePolicy loads a policy OpenShell 0.1.1 accepted in
// the harness spike (network_policies empty, hand-written ordering).
func TestParseYAMLAcceptsSpikePolicy(t *testing.T) {
	spike := `version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc, /proc, /dev/urandom, /var/log, /opt]
  read_write: [/tmp, /dev/null, /dev/ptmx, /dev/pts, /dev/tty, /work/proj]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: "1000"
  run_as_group: "1000"
network_policies: {}
`
	p, err := ParseYAML([]byte(spike))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if len(p.NetworkPolicies) != 0 || p.Process.RunAsUser != "1000" {
		t.Fatalf("parsed %#v", p)
	}
}

func TestParseProfile(t *testing.T) {
	for in, want := range map[string]Profile{"": ProfileOpen, "OPEN": ProfileOpen, " balanced ": ProfileBalanced, "strict": ProfileStrict} {
		got, err := ParseProfile(in)
		if err != nil || got != want {
			t.Fatalf("ParseProfile(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseProfile("permissive"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	// The egress proxy's mode follows the profile; strict renders no
	// egress rule at all (see the goldens).
	for profile, mode := range map[Profile]EgressMode{ProfileOpen: EgressAllowByDefault, ProfileBalanced: EgressAllowlist, ProfileStrict: EgressOff} {
		if got := EgressModeFor(profile); got != mode {
			t.Errorf("EgressModeFor(%s) = %s, want %s", profile, got, mode)
		}
	}
}

func TestValidateRejectsExternalPolicies(t *testing.T) {
	for name, mutate := range map[string]func(*v1.SandboxPolicy){
		"middleware": func(p *v1.SandboxPolicy) {
			p.NetworkMiddlewares = map[string]types.NetworkMiddlewareConfig{"m": {Name: "m"}}
		},
		"read-only and read-write": func(p *v1.SandboxPolicy) { p.Filesystem.ReadOnly = append(p.Filesystem.ReadOnly, "/work/myapp") },
		"nil network policies":     func(p *v1.SandboxPolicy) { p.NetworkPolicies = nil },
	} {
		p := mustRender(t, baseInput(ProfileOpen, "codex"))
		mutate(p)
		if err := Validate(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := Validate(nil); err == nil {
		t.Fatal("nil policy accepted")
	}
}

func mustRender(t *testing.T, in Input) *v1.SandboxPolicy {
	t.Helper()
	p, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
