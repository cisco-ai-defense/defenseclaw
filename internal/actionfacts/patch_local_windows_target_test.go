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

func patchOf(directive, target string) string {
	body := ""
	if directive == "Add File" {
		body = "+x\n"
	}
	return "*** Begin Patch\n*** " + directive + ": " + target + "\n" + body + "*** End Patch"
}

// A typed patch target that names a file below a root the path rules read is
// a path fact, so the path rules judge it: the extended-length and device
// forms of a drive path, the admin share of this machine under every local
// name, and a share of another host.
func TestPatchTargetThatOpensALocalWindowsFileIsAPathFact(t *testing.T) {
	windowsPatchNames(t)
	for _, target := range []string{
		`\\?\C:\Users\fixture\.netrc`, `\\.\C:\Users\fixture\.netrc`, `\\?\c:\Users\fixture\.netrc`,
		`\\localhost\c$\Users\fixture\.netrc`, `\\LOCALHOST\C$\Users\fixture\.netrc`,
		`\\127.0.0.1\C$\Users\fixture\.netrc`, `\\::1\c$\Users\fixture\.netrc`,
		`\\0--1.ipv6-literal.net\c$\Users\fixture\.netrc`, `\\build-host\c$\Users\fixture\.netrc`,
		`\\?\UNC\localhost\c$\Users\fixture\.netrc`, `\\?\UNC\127.0.0.1\C$\Users\fixture\.netrc`,
		`\\localhost/c$/Users/fixture/.netrc`, `\\?\C:/Users/fixture/.netrc`,
		// A share of another host, its admin share included, is the path a
		// Claude Code Write of the same name has (rel-1-0-10:GAP-1052).
		`\\server\share\file.txt`, `\\server\c$\file.txt`, `\\localhost\share\file.txt`,
		`\\localhost\cc$\file.txt`, `\\localhost.example\c$\file.txt`,
		`\\?\UNC\server\share\file.txt`, `\\?\UNC\server\c$\file.txt`, `\\server/c$/file.txt`,
	} {
		for _, directive := range []string{"Add File", "Delete File"} {
			t.Run(directive+" "+target, func(t *testing.T) {
				args, err := json.Marshal(map[string]string{"input": patchOf(directive, target)})
				if err != nil {
					t.Fatal(err)
				}
				facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: `C:\workspace`, DialectHint: DialectPowerShell})
				if !facts.Authoritative() || len(facts.Paths) != 1 || facts.Paths[0].Value != target {
					t.Fatalf("facts = %#v", facts)
				}
			})
		}
	}
}

// A target that names no file below a root the path rules read stays unread:
// a share without a file, a device or namespace that is no drive, a drive
// without a path, and a name with an empty server. The gateway judges such a
// call at the unknown tier (PatchNamesUnplacedTarget).
func TestPatchTargetThatIsNoLocalWindowsFileStaysUnread(t *testing.T) {
	windowsPatchNames(t)
	for _, target := range []string{
		`\\localhost\c$`, `\\localhost\c$\`, `\\server\share`, `\\?\UNC\server\share`,
		`\\?\GLOBALROOT\Device\x\file.txt`,
		`\\.\pipe\file`, `\\.\PhysicalDrive0`, `\\?\C:`, `\\?\C:file.txt`, `\\?\Volume{1234}\file.txt`,
		`\\\localhost\c$\file.txt`, `\\`, `\\?\`, `\\localhost`,
	} {
		t.Run(target, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"input": patchOf("Delete File", target)})
			if err != nil {
				t.Fatal(err)
			}
			facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: `C:\workspace`, DialectHint: DialectPowerShell})
			if facts.Parse.Status != StatusInvalid || facts.Authoritative() || len(facts.Paths) != 0 {
				t.Fatalf("facts = %#v", facts)
			}
		})
	}
}
