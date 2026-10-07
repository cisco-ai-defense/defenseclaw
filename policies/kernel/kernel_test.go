// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernel

import (
	"regexp"
	"strings"
	"testing"

	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

func TestEmbeddedSetLoads(t *testing.T) {
	set, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	ssh, ok := set.Control(ControlSSHPrivateKeyRead)
	if !ok || ssh.RuleID != "PATH-SSH-KEY" || ssh.Access != AccessOpen {
		t.Fatalf("ssh control = %+v", ssh)
	}
	for _, name := range ssh.Files {
		if strings.HasSuffix(name, ".pub") || !strings.HasPrefix(name, ".ssh/id_") {
			t.Fatalf("ssh control names %q; only exact private-key names belong here", name)
		}
	}
	persist, ok := set.Control(ControlPersistenceWrite)
	if !ok || persist.RuleID != "persistence.shell_profile_write" || persist.Access != AccessWrite {
		t.Fatalf("persistence control = %+v", persist)
	}
	if len(set.Connect.ExcludeDestinations) == 0 || set.Observe.RateLimit == "" {
		t.Fatalf("observe/connect not loaded: %+v %+v", set.Observe, set.Connect)
	}
}

// Agent state roots, repository files and provider credentials are never
// enforce-capable (spec 6.2): they would break agents and checkouts.
func TestControlsNeverNameExcludedPaths(t *testing.T) {
	set := MustLoad()
	excluded := []string{".openclaw", ".zeptoclaw", ".config/github-copilot", "CLAUDE.md", "AGENTS.md",
		".mcp.json", "mcp.json", ".aws", ".config/gcloud", ".defenseclaw", ".claude", ".codex", ".cursor"}
	for _, control := range set.Controls {
		for _, p := range append(append([]string{}, control.Files...), control.Dirs...) {
			for _, bad := range excluded {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Fatalf("%s names excluded path %q", control.ID, p)
				}
			}
		}
	}
}

func TestEmbeddedSetFailsWhenSSHControlNamesADirectory(t *testing.T) {
	set := MustLoad()
	bad := Set{Observe: set.Observe, Connect: set.Connect}
	for _, control := range set.Controls {
		if control.ID == ControlSSHPrivateKeyRead {
			control.Dirs = []string{".ssh/keys/"}
		}
		bad.Controls = append(bad.Controls, control)
	}
	if err := validate(bad); err == nil {
		t.Fatal("the ssh control must stay files-only: the exemption is keyed to exact names")
	}
}

func TestDigestShape(t *testing.T) {
	digest := Digest()
	if !regexp.MustCompile(`^sha256:[0-9a-f]{12}$`).MatchString(digest) {
		t.Fatalf("Digest() = %q", digest)
	}
	if !strings.HasPrefix(FullDigest(), digest) || len(FullDigest()) != len("sha256:")+64 {
		t.Fatalf("FullDigest() = %q, Digest() = %q", FullDigest(), digest)
	}
	if !AckMatches(digest) || AckMatches("") || AckMatches("sha256:000000000000") && digest != "sha256:000000000000" {
		t.Fatal("AckMatches")
	}
	for value, want := range map[string]bool{
		"": true, digest: true, "sha256:3f9c2a7d41b0": true,
		"sha256:3F9C2A7D41B0": false, "sha256:3f9c": false, "3f9c2a7d41b0": false, "sha256:3f9c2a7d41b0aa": false,
	} {
		if got := ValidAck(value); got != want {
			t.Errorf("ValidAck(%q) = %v, want %v", value, got, want)
		}
	}
}

// The control set must never reach a per-user or vendor policy directory.
func TestKernelSetNotInPolicyAssets(t *testing.T) {
	assets, err := policyassets.Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range assets {
		if strings.HasPrefix(file.Path, "kernel/") {
			t.Fatalf("policyassets.Files lists %s", file.Path)
		}
	}
}
