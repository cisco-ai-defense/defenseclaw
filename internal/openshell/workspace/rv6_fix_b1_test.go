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
