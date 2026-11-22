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

package workspace

import (
	"os"
	"strings"
	"testing"
)

// rv6Push stages the project again, as a push does, and sends it.
func rv6Push(t *testing.T, e *env, fs *fakeSandbox, name string) {
	t.Helper()
	opts := e.stageOpts(name)
	opts.RewriteSecrets = PlaceholderToken
	st, err := PrepareCopy(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	p, err := PlanPush(bg, PushPlanOptions{DataDir: e.data, Name: name, Stage: st, Exec: fs})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Changes {
		if c.Path == "config.py" {
			t.Errorf("the push sends config.py again (%s): its placeholder was renumbered", c.Status)
		}
	}
	if _, err := p.Send(bg, fs, PushRefuse, ""); err != nil {
		t.Fatal(err)
	}
}

func rv6PullApply(t *testing.T, e *env, fs *fakeSandbox, name string) (*PullResult, *ApplyResult) {
	t.Helper()
	pr := pull(t, e, fs, name)
	ar, err := apply(e, name, ApplyMerge, func(o *ApplyOptions) { o.AcceptSensitive = true })
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return pr, ar
}

// RV6-1 (GAP-0764): a credential in a file that sorts before config.py,
// added after the upload and pushed, takes a new number; config.py keeps
// DC_SECRET_1, so the push does not send it and a pull brings both
// files' agent edits back around the person's values.
func TestB1RV6PushKeepsPlaceholderNumbers(t *testing.T) {
	e, fs, key := s9aCopy(t, "rv6d")
	k2 := "gh" + "p_" + strings.Repeat("Q7", 18)
	writeFile(t, e.project, "a.py", "KEY2 = \""+k2+"\"\n")
	rv6Push(t, e, fs, "rv6d")
	ra, rc := s9aRemote(t, fs, "a.py"), s9aRemote(t, fs, "config.py")
	if strings.Contains(ra+rc, k2) || strings.Contains(ra+rc, key) {
		t.Fatalf("a value went up: a.py=%q config.py=%q", ra, rc)
	}
	if !strings.Contains(rc, "DC_SECRET_1") || !strings.Contains(ra, "DC_SECRET_2") {
		t.Fatalf("placeholders: a.py=%q config.py=%q; want config.py DC_SECRET_1, a.py DC_SECRET_2", ra, rc)
	}
	fs.write(remoteRepo+"/config.py", strings.Replace(rc, "import os", "import os, sys", 1))
	fs.write(remoteRepo+"/a.py", ra+"B = 2\n")
	pr, _ := rv6PullApply(t, e, fs, "rv6d")
	gc, ga := s9aLocal(t, e, "config.py"), s9aLocal(t, e, "a.py")
	if !strings.Contains(gc, "import os, sys") || !strings.Contains(gc, key) {
		t.Errorf("config.py = %q (warnings %q): want the agent's edit and the person's value", gc, pr.Review.Warnings)
	}
	if !strings.Contains(ga, "B = 2") || !strings.Contains(ga, k2) {
		t.Errorf("a.py = %q: want the agent's edit and the pushed value", ga)
	}
	noPlaceholderIn(t, e)
}

// RV6-1 (GAP-0764): a credential pushed after the upload is a replaced
// file on pull. The agent's edit lands around the person's value, and a
// branch or patch never holds its placeholder or its value.
func TestB1RV6PushedSecretPullsBack(t *testing.T) {
	e, fs, key := s9aCopy(t, "rv6c")
	k2 := "gh" + "p_" + strings.Repeat("Q7", 18)
	writeFile(t, e.project, "zz.py", "A = 1\nKEY2 = \""+k2+"\"\n")
	rv6Push(t, e, fs, "rv6c")
	remote := s9aRemote(t, fs, "zz.py")
	if strings.Contains(remote, k2) || !strings.Contains(remote, "DC_SECRET_2") {
		t.Fatalf("sandbox zz.py = %q", remote)
	}
	fs.write(remoteRepo+"/zz.py", remote+"B = 2\n")
	_, ar := rv6PullApply(t, e, fs, "rv6c")
	if ar != nil && ar.Branch != "" {
		all := e.git(e.project, "log", "-p", "--format=%H %s", ar.Branch)
		if strings.Contains(all, k2) || strings.Contains(all, key) || strings.Contains(all, "DC_SECRET_") {
			t.Errorf("branch %s holds a value or a placeholder", ar.Branch)
		}
	}
	if ar != nil && ar.PatchPath != "" {
		if b, _ := os.ReadFile(ar.PatchPath); strings.Contains(string(b), "DC_SECRET_") || strings.Contains(string(b), k2) {
			t.Errorf("patch holds a value or a placeholder")
		}
	}
	if got := s9aLocal(t, e, "zz.py"); got != "A = 1\nKEY2 = \""+k2+"\"\nB = 2\n" {
		t.Errorf("zz.py = %q", got)
	}
	noPlaceholderIn(t, e)
}

// RV6-2 (GAP-0765): a blank line added or removed above or below the
// credential line is an ordinary edit: it lands, with no "moved" note.
func TestB1RV6BlankLineEditsLand(t *testing.T) {
	k := b1Key(0)
	up := "import os\n\nTOKEN = \"" + k + "\"\n\ndef main():\n    print(TOKEN)\n"
	cases := map[string]string{
		"add-blank-above":     "import os\n\n\nTOKEN = \"DC_SECRET_1\"\n\ndef main():\n    print(TOKEN)\n",
		"drop-blank-above":    "import os\nTOKEN = \"DC_SECRET_1\"\n\ndef main():\n    print(TOKEN)\n",
		"add-blank-below":     "import os\n\nTOKEN = \"DC_SECRET_1\"\n\n\ndef main():\n    print(TOKEN)\n",
		"drop-blank-below":    "import os\n\nTOKEN = \"DC_SECRET_1\"\ndef main():\n    print(TOKEN)\n",
		"add-def-above-blank": "import os\n\ndef f():\n    pass\n\nTOKEN = \"DC_SECRET_1\"\n\ndef main():\n    print(TOKEN)\n",
	}
	for n, agent := range cases {
		t.Run(n, func(t *testing.T) {
			e, fs := rv5Launch(t, "rv6b", map[string]string{"config.py": up}, "", PlaceholderToken)
			fs.write(remoteRepo+"/config.py", agent)
			pr, _ := rv6PullApply(t, e, fs, "rv6b")
			want := strings.Replace(agent, "DC_SECRET_1", k, 1)
			if got := s9aLocal(t, e, "config.py"); got != want {
				t.Errorf("config.py = %q, want %q (warnings %q)", got, want, pr.Review.Warnings)
			}
			for _, f := range pr.Review.Flags {
				if f.Kind == RiskSecretContext {
					t.Errorf("a blank-line edit is flagged: %+v", f)
				}
			}
		})
	}
}

// RV6-2: a credential line moved past other lines still keeps the agent's
// change out.
func TestB1RV6MovedLineStillOut(t *testing.T) {
	k := b1Key(0)
	up := "import os\n\nTOKEN = \"" + k + "\"\n\ndef main():\n    print(TOKEN)\n"
	e, fs := rv5Launch(t, "rv6m", map[string]string{"config.py": up}, "", PlaceholderToken)
	fs.write(remoteRepo+"/config.py", "import os\n\n\ndef main():\n    print(TOKEN)\nTOKEN = \"DC_SECRET_1\"\n")
	pr := pull(t, e, fs, "rv6m")
	if _, err := apply(e, "rv6m", ApplyMerge, func(o *ApplyOptions) { o.AcceptSensitive = true }); err == nil {
		if got := s9aLocal(t, e, "config.py"); got != up {
			t.Errorf("config.py = %q, want the person's file (warnings %q)", got, pr.Review.Warnings)
		}
	}
	if !strings.Contains(strings.Join(pr.Review.Warnings, "\n"), "moved") {
		t.Errorf("no moved note: %q", pr.Review.Warnings)
	}
}

// RV6-3 (GAP-0766): the agent wraps the credential line in place, inside a
// string it sends. The line keeps its place, so the change lands, but the
// review names the file and line.
func TestB1RV6WrapInPlaceIsFlagged(t *testing.T) {
	e, fs, key := s9aCopy(t, "rv6a")
	fs.write(remoteRepo+"/config.py", "import os\nx = \"\"\"\nTOKEN = \"DC_SECRET_1\"\n\"\"\"\nsend(x)\nprint(TOKEN)\n")
	pr, _ := rv6PullApply(t, e, fs, "rv6a")
	if got := s9aLocal(t, e, "config.py"); !strings.Contains(got, "send(x)") || !strings.Contains(got, key) {
		t.Fatalf("config.py = %q: want the agent's change with the person's value", got)
	}
	flagged := false
	for _, f := range pr.Review.Flags {
		flagged = flagged || (f.Kind == RiskSecretContext && f.Path == "config.py" && f.Label == "config.py:3")
	}
	if !flagged {
		t.Errorf("no secret-context flag on config.py:3: %+v", pr.Review.Flags)
	}
	if !strings.Contains(strings.Join(pr.Review.Warnings, "\n"), "config.py: line 3 holds your credential") {
		t.Errorf("no note: %q", pr.Review.Warnings)
	}
}
