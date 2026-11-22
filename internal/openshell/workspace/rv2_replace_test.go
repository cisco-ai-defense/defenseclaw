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

package workspace

import (
	"errors"
	"reflect"
	"testing"
)

// RV2 N2: the plan names what --mine would remove; PushMine refuses it
// with *PushReplaceError and PushMineReplace sends it.
func TestPushMineReplaceNamesAndSends(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := pushLaunch(t, e, "r1")
	fs.write(rec.RemoteDir+"/out", "agent\n")
	fs.write(rec.RemoteDir+"/notes/a.md", "agent\n")
	writeFile(t, e.project, "out/report.txt", "laptop\n")
	writeFile(t, e.project, "notes", "laptop\n")
	p := planPush(t, e, "r1", fs)
	got := map[string]string{}
	for _, c := range p.Replacing() {
		got[c.Path] = c.Replaces + " | " + c.ReplaceNote()
	}
	want := map[string]string{
		"out/report.txt": "out | the agent has a file or link at out; sending yours removes it",
		"notes":          "notes | the agent has a folder here; sending yours removes that folder",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("replacing = %q, want %q", got, want)
	}
	var repl *PushReplaceError
	if _, err := p.Send(bg, fs, PushMine, ""); !errors.As(err, &repl) || len(repl.Changes) != 2 {
		t.Fatalf("send --mine = %v, want *PushReplaceError with 2 paths", err)
	}
	if _, err := p.Send(bg, fs, PushMineReplace, ""); err != nil {
		t.Fatalf("send --mine --replace: %v", err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "out/report.txt", "laptop\n", "notes", "laptop\n")
}
