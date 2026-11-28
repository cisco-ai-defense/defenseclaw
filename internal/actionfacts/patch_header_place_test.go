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
	"runtime"
	"slices"
	"testing"
)

// windowsPatchNames reads patch targets as the patch tool of a Windows host
// does, for the rest of the test (patchTargetsAreWindowsNames).
func windowsPatchNames(t *testing.T) {
	t.Helper()
	saved := patchTargetsAreWindowsNames
	patchTargetsAreWindowsNames = true
	t.Cleanup(func() { patchTargetsAreWindowsNames = saved })
}

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

// patchHomeTargets are the home forms, which the patch tool expands on no
// host; patchWindowsOnlyUnplacedTargets are the names only a Windows host
// leaves unplaced (a drive-relative path, a device or namespace path, a share
// without a file).
var (
	patchHomeTargets                = []string{"~", "~/notes.txt", `~\notes.txt`}
	patchWindowsOnlyUnplacedTargets = []string{`D:notes.txt`, `\\.\pipe\notes`, `\\?\Volume{1234}\notes.txt`,
		`\\server\share`, `\\localhost\c$\`, `\\?\C:`, `\\`}
)

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
					if PatchNamesUnplacedTarget(Input{Tool: "apply_patch", Args: args}) {
						t.Fatal("a placed header is reported unplaced")
					}
				})
			}
		}
	}
}

// A header no reader places (a home form the tool does not expand, a
// drive-relative path, a device or namespace path, a share without a file)
// still names a file the tool writes. That file is no fact, and
// PatchNamesUnplacedTarget reports it, so the gateway judges it at the unknown
// tier instead of allowing it (GAP-1052). The placed file of the same envelope
// stays a fact: the source a Move to such a name removes is a delete fact
// (rel-1-0-10:GAP-1055). An envelope the tool rejects for its syntax writes
// nothing and is not reported.
func TestPatchHeaderNoReaderPlacesIsUnplaced(t *testing.T) {
	windowsPatchNames(t)
	for _, target := range slices.Concat(patchHomeTargets, patchWindowsOnlyUnplacedTargets) {
		for directive, envelope := range patchHeaderEnvelopes(target) {
			for _, field := range patchHeaderFields {
				t.Run(directive+" "+field+" "+target, func(t *testing.T) {
					args, err := json.Marshal(map[string]string{field: envelope.text})
					if err != nil {
						t.Fatal(err)
					}
					facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: `C:\workspace`, DialectHint: DialectPowerShell})
					if directive == "move" {
						if !facts.Authoritative() || len(facts.Paths) != 1 || facts.Paths[0].Value != "notes.txt" ||
							facts.Paths[0].Access != PathAccessDelete {
							t.Fatalf("the moved source is not the one delete fact: %#v %#v", facts.Parse, facts.Paths)
						}
					} else if facts.Authoritative() {
						t.Fatalf("an unplaced header is a fact: %#v", facts.Paths)
					}
					if !PatchNamesUnplacedTarget(Input{Tool: "apply_patch", Args: args}) {
						t.Fatal("the unplaced header is not reported")
					}
					if PatchNamesUnplacedTarget(Input{Tool: "Write", Args: args}) {
						t.Fatal("a tool that is no patch tool is reported")
					}
				})
			}
		}
		t.Run("rejected "+target, func(t *testing.T) {
			// No End Patch line: the tool applies nothing.
			args, _ := json.Marshal(map[string]string{"command": "*** Begin Patch\n*** Add File: " + target + "\n+x\n"})
			if PatchNamesUnplacedTarget(Input{Tool: "apply_patch", Args: args}) {
				t.Fatal("a rejected envelope is reported")
			}
			// A line that is no part of the grammar after the header.
			args, _ = json.Marshal(map[string]string{"command": "*** Begin Patch\n*** Add File: " + target + "\nx\n*** End Patch"})
			if PatchNamesUnplacedTarget(Input{Tool: "apply_patch", Args: args}) {
				t.Fatal("an envelope with a stray line is reported")
			}
		})
	}
}

// Off Windows the patch tool reads a backslash as a character of a file name
// and a colon after a letter as nothing special, so a header that only a
// Windows host leaves unplaced is a relative name of the working folder: the
// path rules place it, it is the fact its directive gives, and the call is not
// reported unplaced, as rel read it (rel-1-0-10:GAP-1056). The home forms stay
// unplaced on every host (TestPatchHeaderNoReaderPlacesIsUnplaced).
func TestPatchHeaderOffWindowsIsARelativeName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a Windows host reads these names as Windows names (TestPatchHeaderNoReaderPlacesIsUnplaced)")
	}
	for _, target := range patchWindowsOnlyUnplacedTargets {
		for directive, envelope := range patchHeaderEnvelopes(target) {
			for _, field := range patchHeaderFields {
				t.Run(directive+" "+field+" "+target, func(t *testing.T) {
					args, err := json.Marshal(map[string]string{field: envelope.text})
					if err != nil {
						t.Fatal(err)
					}
					facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: "/srv/app"})
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
					if PatchNamesUnplacedTarget(Input{Tool: "apply_patch", Args: args}) {
						t.Fatal("a relative name is reported unplaced")
					}
				})
			}
		}
	}
	for _, target := range patchHomeTargets {
		args, _ := json.Marshal(map[string]string{"command": "*** Begin Patch\n*** Add File: " + target + "\n+x\n*** End Patch"})
		if !PatchNamesUnplacedTarget(Input{Tool: "apply_patch", Args: args}) {
			t.Fatalf("the home form %q is not reported unplaced", target)
		}
	}
}
