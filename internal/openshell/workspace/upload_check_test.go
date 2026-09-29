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
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uploadsElsewhere is an Uploader whose uploads land in another sandbox,
// as ssh connection sharing made the OpenShell CLI's do.
type uploadsElsewhere struct{ to *fakeSandbox }

func (u uploadsElsewhere) Upload(ctx context.Context, sandbox, localPath, remoteDir string) error {
	return u.to.Upload(ctx, "the other sandbox", localPath, remoteDir)
}

// otherFakeSandbox is another fake sandbox beside newFakeSandbox's.
func otherFakeSandbox(t *testing.T, e *env) *fakeSandbox {
	root, err := os.MkdirTemp(e.root, "other-fs-")
	if err != nil {
		t.Fatal(err)
	}
	mustMkdir(t, filepath.Join(root, "sandbox"))
	return &fakeSandbox{t: t, root: root, home: e.home}
}

// execTwice runs every command twice and answers with the second run, as
// an Idempotent exec retried after an attempt that answered nothing.
type execTwice struct{ *fakeSandbox }

func (x execTwice) Exec(ctx context.Context, sandbox string, req ExecRequest) (*ExecResult, error) {
	if req.Idempotent {
		if _, err := x.fakeSandbox.Exec(ctx, sandbox, req); err != nil {
			return nil, err
		}
	}
	return x.fakeSandbox.Exec(ctx, sandbox, req)
}

// uploadMarkers lists the upload markers under root.
func uploadMarkers(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), uploadMarkerPrefix) {
			rel, _ := filepath.Rel(root, p)
			found = append(found, rel)
		}
		return err
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return found
}

// An upload the OpenShell CLI reports done over its ssh session is
// confirmed over the exec API in the sandbox it named: one that ssh
// connection sharing carried into another sandbox fails the run instead
// of leaving the named sandbox without its copy.
func TestUploadMustArriveInTheNamedSandbox(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	box, other := newFakeSandbox(t, e), otherFakeSandbox(t, e)
	if _, err := Stage(bg, e.stageOpts("c1")); err != nil {
		t.Fatal(err)
	}

	_, err := Upload(bg, e.data, "c1", uploadsElsewhere{other}, box)
	var missing *UploadNotArrivedError
	if !errors.As(err, &missing) || !errors.Is(err, ErrUploadNotArrived) || !missing.Missing ||
		err.Error() != "workspace: the upload to c1 did not arrive: openshell reported it done, but in c1 "+remoteRepo+" is not there; "+
			"the files went elsewhere, for example into another sandbox through an ssh connection shared between sandboxes" {
		t.Fatalf("upload into another sandbox = %v", err)
	}
	if !pathExists(other.local(remoteRepo + "/.git")) {
		t.Fatal("the stand-in upload did not land in the other sandbox")
	}
	rec, err := LoadCopy(e.data, "c1")
	if err != nil || rec.UploadedAt != nil || rec.Stage == "" || !pathExists(rec.Stage) {
		t.Fatalf("a copy that did not arrive was recorded as uploaded: %+v, %v", rec, err)
	}
	if left := uploadMarkers(t, rec.Stage); len(left) != 0 {
		t.Fatalf("the staged copy kept the upload marker: %v", left)
	}

	// The named sandbox has the folder (an earlier copy), not this upload.
	mustMkdir(t, box.local(remoteRepo))
	_, err = Upload(bg, e.data, "c1", uploadsElsewhere{otherFakeSandbox(t, e)}, box)
	if !errors.As(err, &missing) || missing.Missing || !strings.Contains(err.Error(), "but in c1 "+remoteRepo+" has no "+uploadMarkerPrefix) {
		t.Fatalf("upload beside an earlier copy = %v", err)
	}

	// Into the named sandbox, with the confirmation run twice (a retry):
	// it arrives, and no marker is left in the copy the agent sees.
	rec, err = Upload(bg, e.data, "c1", box, execTwice{box})
	if err != nil || rec.UploadedAt == nil {
		t.Fatalf("upload = %+v, %v", rec, err)
	}
	if left := uploadMarkers(t, box.local(remoteRepo)); len(left) != 0 {
		t.Fatalf("upload markers left in the copy: %v", left)
	}
	if _, err := EstablishBaseline(bg, e.data, "c1", box); err != nil {
		t.Fatal(err)
	}
	if pr := pull(t, e, box, "c1"); !pr.Empty() {
		t.Fatalf("a fresh copy has changes: %s", changePaths(pr.Changes))
	}
}

// A plain folder goes up in two uploads (the files, then DefenseClaw's git
// directory for it), each confirmed; one receipt at most stays behind, in
// DefenseClaw's state directory.
func TestPlainCopyUploadsAreEachConfirmed(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	rec, box := launchCopy(t, e, "p1", nil)
	if rec.Kind != CopyPlain {
		t.Fatalf("kind = %s", rec.Kind)
	}
	if left := uploadMarkers(t, box.local("/sandbox/work")); len(left) != 0 {
		t.Fatalf("upload markers left in the copy: %v", left)
	}
	if left := uploadMarkers(t, box.local(remoteStateDir)); len(left) != 1 || !strings.HasPrefix(left[0], "uploads/"+uploadMarkerPrefix) {
		t.Fatalf("state directory markers = %v, want the last upload's receipt", left)
	}
}

// The second upload of a plain folder, its git directory, is confirmed on
// its own: the files arriving says nothing about it.
func TestPlainCopyGitDirectoryMustArrive(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	box, other := newFakeSandbox(t, e), otherFakeSandbox(t, e)
	if _, err := Stage(bg, e.stageOpts("p2")); err != nil {
		t.Fatal(err)
	}
	second := &splitUploader{first: box, rest: other}
	if _, err := Upload(bg, e.data, "p2", second, box); !errors.Is(err, ErrUploadNotArrived) || !strings.Contains(err.Error(), "in p2 /sandbox/.dc/git is not there") {
		t.Fatalf("upload of the git directory into another sandbox = %v", err)
	}
}

// splitUploader sends the first upload to first and the others to rest.
type splitUploader struct {
	first, rest Uploader
	n           int
}

func (s *splitUploader) Upload(ctx context.Context, sandbox, localPath, remoteDir string) error {
	s.n++
	if s.n == 1 {
		return s.first.Upload(ctx, sandbox, localPath, remoteDir)
	}
	return s.rest.Upload(ctx, sandbox, localPath, remoteDir)
}

// A refresh whose upload goes astray leaves the copy state as it was, as
// any failed refresh does.
func TestRefreshUploadMustArrive(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	before, box := launchCopy(t, e, "c1", nil)
	opts := e.refreshOpts("c1", box)
	opts.Upload = uploadsElsewhere{otherFakeSandbox(t, e)}
	if _, err := Refresh(bg, opts); !errors.Is(err, ErrUploadNotArrived) {
		t.Fatalf("refresh into another sandbox = %v", err)
	}
	rec, err := LoadCopy(e.data, "c1")
	if err != nil || rec.Baseline != before.Baseline || rec.BaseGit != before.BaseGit || !pathExists(rec.BaseGit) {
		t.Fatalf("copy record changed: %+v, %v", rec, err)
	}
	if left := copyLeftovers(t, e, "c1"); len(left) > 0 {
		t.Fatalf("left behind %v", left)
	}
}
