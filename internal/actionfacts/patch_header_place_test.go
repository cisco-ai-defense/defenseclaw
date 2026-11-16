// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

type patchHeaderEnvelope struct {
	text   string
	access PathAccess
}

// patchHeaderEnvelopes are the envelopes of every directive that names a
// file, with target as the file it writes or removes.
func patchHeaderEnvelopes(target string) map[string]patchHeaderEnvelope {
	return map[string]patchHeaderEnvelope{
		"add":    {"*** Begin Patch\n*** Add File: " + target + "\n+x\n*** End Patch", PathAccessWrite},
		"update": {"*** Begin Patch\n*** Update File: " + target + "\n@@\n-a\n+b\n*** End Patch", PathAccessWrite},
		"delete": {"*** Begin Patch\n*** Delete File: " + target + "\n*** End Patch", PathAccessDelete},
		"move": {"*** Begin Patch\n*** Update File: notes.txt\n*** Move to: " + target + "\n@@\n-a\n+b\n*** End Patch",
			PathAccessWrite},
	}
}

// patchHeaderFields are the patch fields of the tools that send an envelope:
// Codex apply_patch (command, input), OpenCode V2 patch (patchText, mapped to
// apply_patch by hookpaths.ConnectorActionTool) and the other spellings the
// reader takes.
var patchHeaderFields = []string{"command", "input", "patch", "patchText", "patch_text"}

// A header that names a file of a share, of this machine or of another host,
// admin shares included, is the write fact a Claude Code Write or Edit of the
// same name is, in every directive and every patch field: the path rules
// judge it, so the patch is never weaker than that write
// (rel-1-0-10:GAP-1052, GAP-0947).
func TestPatchHeaderOfAShareIsAWriteFact(t *testing.T) {
	for _, target := range []string{
		`\\WINHOST\c$\Users\fixture\.netrc`, `\\winhost\C$\Users\fixture\.netrc`, `\\WINHOST\d$\data\fixture.txt`,
		`\\WINHOST/c$/Users/fixture/.netrc`, `\\?\UNC\WINHOST\c$\Users\fixture\.netrc`,
		`\\fileserver\home$\fixture\.netrc`, `\\fileserver\share\fixture\notes.txt`, `\\10.0.0.9\c$\Users\fixture\.netrc`,
	} {
		for directive, envelope := range patchHeaderEnvelopes(target) {
			for _, field := range patchHeaderFields {
				t.Run(directive+" "+field+" "+target, func(t *testing.T) {
					args, err := json.Marshal(map[string]string{field: envelope.text})
					if err != nil {
						t.Fatal(err)
					}
					facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: `C:\workspace`, DialectHint: DialectPowerShell})
					if !facts.Authoritative() {
						t.Fatalf("parse = %#v", facts.Parse)
					}
					found := false
					for _, path := range facts.Paths {
						found = found || path.Value == target && path.Access == envelope.access
					}
					if !found {
						t.Fatalf("no %s fact for the header: %#v", envelope.access, facts.Paths)
					}
					if PatchNamesUnplacedTarget("apply_patch", args) {
						t.Fatal("a placed header is reported unplaced")
					}
				})
			}
		}
	}
}

// A header no reader places (a home form the tool does not expand, a
// drive-relative path, a device or namespace path, a share without a file)
// still names a file the tool writes. The call has no write fact, and
// PatchNamesUnplacedTarget reports it, so the gateway judges it at the unknown
// tier instead of allowing it (GAP-1052). An envelope the tool rejects for its
// syntax writes nothing and is not reported.
func TestPatchHeaderNoReaderPlacesIsUnplaced(t *testing.T) {
	for _, target := range []string{
		"~", "~/notes.txt", `~\notes.txt`, `C:notes.txt`, `\\.\pipe\notes`, `\\?\Volume{1234}\notes.txt`,
		`\\server\share`, `\\localhost\c$\`, `\\?\C:`, `\\`,
	} {
		for directive, envelope := range patchHeaderEnvelopes(target) {
			for _, field := range patchHeaderFields {
				t.Run(directive+" "+field+" "+target, func(t *testing.T) {
					args, err := json.Marshal(map[string]string{field: envelope.text})
					if err != nil {
						t.Fatal(err)
					}
					facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: `C:\workspace`, DialectHint: DialectPowerShell})
					if facts.Authoritative() {
						t.Fatalf("an unplaced header is a fact: %#v", facts.Paths)
					}
					if !PatchNamesUnplacedTarget("apply_patch", args) {
						t.Fatal("the unplaced header is not reported")
					}
					if PatchNamesUnplacedTarget("Write", args) {
						t.Fatal("a tool that is no patch tool is reported")
					}
				})
			}
		}
		t.Run("rejected "+target, func(t *testing.T) {
			// No End Patch line: the tool applies nothing.
			args, _ := json.Marshal(map[string]string{"command": "*** Begin Patch\n*** Add File: " + target + "\n+x\n"})
			if PatchNamesUnplacedTarget("apply_patch", args) {
				t.Fatal("a rejected envelope is reported")
			}
			// A line that is no part of the grammar after the header.
			args, _ = json.Marshal(map[string]string{"command": "*** Begin Patch\n*** Add File: " + target + "\nx\n*** End Patch"})
			if PatchNamesUnplacedTarget("apply_patch", args) {
				t.Fatal("an envelope with a stray line is reported")
			}
		})
	}
}
