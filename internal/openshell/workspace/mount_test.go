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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func mustPlan(t *testing.T, e *env, name string, mutate func(*MountOptions)) *MountPlan {
	t.Helper()
	opts := e.mountOpts(name)
	if mutate != nil {
		mutate(&opts)
	}
	plan, err := PlanMount(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// maskReasons maps each masked path to why it was masked.
func maskReasons(plan *MountPlan) map[string]string {
	out := map[string]string{}
	for _, m := range plan.Masked {
		out[m.Rel] = m.Reason
	}
	return out
}

func TestPlanMountGitRepoProtectsHostExecutableState(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".env", "API_KEY=abc\n")
	writeFile(t, e.project, "certs/dev.pem", "not really a key\n")
	writeFile(t, e.project, ".env.example", "API_KEY=\n")

	plan := mustPlan(t, e, "dc-claude-myapp-7f3a", nil)
	if plan.Target != "/work/myapp" || plan.Project != e.project || plan.RepoName != "myapp" ||
		plan.RunAsUser != strconv.Itoa(os.Getuid()) || plan.RunAsGroup != strconv.Itoa(os.Getgid()) {
		t.Fatalf("plan identity: %+v", plan)
	}
	if strings.Join(plan.ReadWrite, ",") != "/work/myapp" || plan.Labels[ProjectLabelKey] != ProjectKey(e.project) || plan.Labels[ModeLabelKey] != "mount" {
		t.Fatalf("ReadWrite = %v, labels = %v", plan.ReadWrite, plan.Labels)
	}
	want := map[string]struct {
		kind MountKind
		ro   bool
	}{
		"/work/myapp":                      {MountProject, false},
		"/work/myapp/.git":                 {MountPin, false},
		"/work/myapp/.git/config":          {MountProtect, true},
		"/work/myapp/.git/config.worktree": {MountProtect, true},
		"/work/myapp/.git/hooks":           {MountProtect, true},
		"/work/myapp/.git/commondir":       {MountProtect, true},
		"/work/myapp/.env":                 {MountMask, true},
		"/work/myapp/certs/dev.pem":        {MountMask, true},
		// The folder of a mask is pinned so it cannot be renamed away.
		"/work/myapp/certs": {MountPin, false},
	}
	for target, w := range want {
		if m, ok := mountByTarget(plan, target); !ok || m.Kind != w.kind || m.ReadOnly != w.ro {
			t.Fatalf("%s = %+v, %v; want kind %s ro %v (mounts %+v)", target, m, ok, w.kind, w.ro, plan.Mounts)
		}
	}
	// .env.example is a template and stays visible; nothing else is mounted.
	if len(plan.Mounts) != len(want) {
		t.Fatalf("unexpected extra mounts: %+v", plan.Mounts)
	}
	// Parents strictly before children.
	for i, m := range plan.Mounts {
		for _, later := range plan.Mounts[i+1:] {
			if strings.HasPrefix(m.Target, later.Target+"/") {
				t.Fatalf("%s is mounted before its parent %s", m.Target, later.Target)
			}
		}
	}
	// The commondir pin exists on the host and is a no-op for git.
	wantFiles(t, e.project, ".git/commondir", commondirPin)
	if out := e.git(e.project, "status", "--porcelain"); strings.Contains(out, "fatal") {
		t.Fatalf("git broke with the pin: %s", out)
	}
	// Masks bind an empty, read-only file owned by the operator.
	m, _ := mountByTarget(plan, "/work/myapp/.env")
	if info, err := os.Stat(m.Source); err != nil || info.Size() != 0 || info.Mode().Perm() != 0o444 || !strings.HasPrefix(m.Source, e.data) {
		t.Fatalf("mask source %s: %v %v", m.Source, info, err)
	}
	lines := strings.Join(plan.Summary().Lines(), "\n")
	for _, s := range []string{"~/code/myapp → /work/myapp (live)", ".env", "certs/dev.pem", "--unmask", ".git/hooks", ".git/config.worktree", "(read-only)", "Not visible"} {
		if !strings.Contains(lines, s) {
			t.Fatalf("banner missing %q:\n%s", s, lines)
		}
	}

	// The driver config is structpb-compatible and lists every mount.
	if _, err := structpb.NewStruct(plan.DriverConfig()); err != nil {
		t.Fatalf("DriverConfig is not structpb-compatible: %v", err)
	}
	raw, err := plan.DriverConfigJSON()
	var decoded struct {
		Docker struct {
			Mounts []struct {
				Type     string `json:"type"`
				Target   string `json:"target"`
				ReadOnly bool   `json:"read_only"`
			} `json:"mounts"`
		} `json:"docker"`
	}
	if err != nil || json.Unmarshal([]byte(raw), &decoded) != nil || len(decoded.Docker.Mounts) != len(plan.Mounts) ||
		decoded.Docker.Mounts[0].Type != "bind" || decoded.Docker.Mounts[0].Target != "/work/myapp" || decoded.Docker.Mounts[0].ReadOnly {
		t.Fatalf("driver config = %s, %v", raw, err)
	}

	// ScanSecrets finds what a mount planned now would mask, a secret file
	// added after the mount was planned included, and creates nothing.
	writeFile(t, e.project, "deploy/id_rsa", "not a real key\n")
	writeFile(t, e.project, "kept.env", "Y=2\n")
	opts := e.mountOpts("s-scan-only")
	opts.Unmask = []string{"kept.env"}
	masks, err := ScanSecrets(bg, opts)
	var rels []string
	for _, m := range masks {
		rels = append(rels, m.Rel)
	}
	if err != nil || strings.Join(rels, ",") != ".env,certs/dev.pem,deploy/id_rsa" {
		t.Fatalf("rescan = %v, %v; want .env, certs/dev.pem and deploy/id_rsa", rels, err)
	}
	wantFiles(t, e.data, "sandboxes/s-scan-only", absent)
}

// TestPlanMountMasksTrackedFilesWithTheirOwnWorkingCopy: being tracked
// only exempts a file whose working copy is exactly its committed copy,
// which the sandbox can read from .git anyway. Local edits, and entries
// git was told to ignore (skip-worktree, assume-unchanged), are masked by
// name and scanned by content like untracked files.
func TestPlanMountMasksTrackedFilesWithTheirOwnWorkingCopy(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	fakeKey := "key AKIA" + strings.Repeat("Z", 16) + "\n"
	for rel, content := range map[string]string{
		"testdata/server.key": "fixture\n",
		"config/local.env":    "TOKEN=placeholder\n",
		"deploy/prod.env":     "TOKEN=placeholder\n",
		"ops/ci.env":          "TOKEN=placeholder\n",
		"settings.py":         "KEY = 'placeholder'\n",
		"config/app.yaml":     "key: placeholder\n",
		"docs/example.md":     fakeKey,
	} {
		writeFile(t, e.project, rel, content)
	}
	e.git(e.project, "add", "-A", "-f")
	e.git(e.project, "commit", "-q", "-m", "tracked")
	e.git(e.project, "update-index", "--skip-worktree", "deploy/prod.env", "config/app.yaml")
	e.git(e.project, "update-index", "--assume-unchanged", "ops/ci.env")
	for _, rel := range []string{"config/local.env", "deploy/prod.env", "ops/ci.env"} {
		writeFile(t, e.project, rel, "TOKEN=marker-local\n")
	}
	writeFile(t, e.project, "settings.py", fakeKey)
	writeFile(t, e.project, "config/app.yaml", fakeKey)

	plan := mustPlan(t, e, "s1", nil)
	reasons := maskReasons(plan)
	for rel, want := range map[string]string{
		"config/local.env": "name", // edited
		"deploy/prod.env":  "name", // skip-worktree
		"ops/ci.env":       "name", // assume-unchanged
		"settings.py":      "content:CS-SEC-AWS-KEY",
		"config/app.yaml":  "content:CS-SEC-AWS-KEY", // skip-worktree, unchanged size
	} {
		if reasons[rel] != want {
			t.Errorf("%s: mask reason %q, want %q (masked: %v)", rel, reasons[rel], want, reasons)
		}
	}
	for _, rel := range []string{"testdata/server.key", "docs/example.md"} {
		if _, ok := reasons[rel]; ok {
			t.Errorf("%s holds its committed bytes but was masked", rel)
		}
	}
	if strings.Join(plan.TrackedSecrets, ",") != "testdata/server.key" || !strings.Contains(strings.Join(plan.Warnings, "\n"), "hold exactly their committed contents") {
		t.Fatalf("TrackedSecrets = %v, warnings = %v", plan.TrackedSecrets, plan.Warnings)
	}
	if plan := mustPlan(t, e, "s2", func(o *MountOptions) { o.MaskTracked = true }); len(plan.TrackedSecrets) != 0 {
		t.Fatalf("MaskTracked left %v visible", plan.TrackedSecrets)
	}
}

// TestTrackedEntryHolds: a working copy holds its committed bytes only for
// a regular file whose blob id (SHA-1 or SHA-256) matches; comparing
// tracked files is bounded.
func TestTrackedEntryHolds(t *testing.T) {
	const sha1, sha256 = "5abed26af8585d58b8923135234ca8d1d77128b4", "52c2fcd945b8573594a0976f8a75079d8c0a3e0b2c03f7f50eb46cf94067c8bb"
	for _, tc := range []struct {
		mode, oid, data string
		want            bool
	}{
		{"100644", sha1, "marker\n", true},
		{"100755", sha1, "marker\n", true},
		{"100644", sha256, "marker\n", true},
		{"100644", sha1, "marker!\n", false},
		{"120000", sha1, "marker\n", false},
		{"100644", "5abed26a", "marker\n", false},
	} {
		if got := (trackedEntry{mode: tc.mode, oid: tc.oid}).holds([]byte(tc.data)); got != tc.want {
			t.Errorf("%s %s holds %q = %v, want %v", tc.mode, tc.oid, tc.data, got, tc.want)
		}
	}
	root := t.TempDir()
	writeFile(t, root, "a.txt", "one\n")
	writeFile(t, root, "b.txt", "two\n")
	entry := trackedEntry{mode: "100644", oid: strings.Repeat("0", 40), watched: true}
	scan, err := detectSecrets(root, secretScanOptions{tracked: map[string]trackedEntry{"a.txt": entry, "b.txt": entry},
		contentScan: true, detector: DefaultSecretDetector(), maxTrackedReads: 1})
	if err != nil || !strings.Contains(strings.Join(scan.warnings, "\n"), "1 tracked file(s) past the first 1") {
		t.Fatalf("warnings = %v, %v", scan.warnings, err)
	}
}

func TestPlanMountUnmaskTrackedAndContentSecrets(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	// Tracked secret-looking fixture: stays visible, reported.
	writeFile(t, e.project, "testdata/server.key", "fixture\n")
	e.git(e.project, "add", "-f", "testdata/server.key")
	e.git(e.project, "commit", "-q", "-m", "fixture")
	writeFile(t, e.project, ".env", "X=1\n")
	writeFile(t, e.project, ".env.local", "X=2\n")
	writeFile(t, e.project, "notes/aws.txt", "key AKIA"+strings.Repeat("Z", 16)+"\n")
	writeFile(t, e.project, ".aws/credentials", "[default]\n")
	writeFile(t, e.project, "config/prod.yaml", "db: secret\n")
	// A secret hard-linked from outside the project is masked with a warning.
	outside := filepath.Join(e.home, "outside-secret")
	must(t, os.WriteFile(outside, []byte("k"), 0o600))
	linked := os.Link(outside, filepath.Join(e.project, "linked.env")) == nil

	plan := mustPlan(t, e, "s2", func(o *MountOptions) {
		o.Unmask = []string{".env.local", filepath.Join(e.project, "notes")}
		o.Masks = []string{"config/prod.yaml"}
	})
	hard := false
	for _, m := range plan.Masked {
		hard = hard || m.Rel == "linked.env" && m.Hardlinked
	}
	if linked && (!hard || !strings.Contains(strings.Join(plan.Warnings, "\n"), "hard links")) {
		t.Fatalf("masked = %+v, warnings = %v; want linked.env masked as hard-linked", plan.Masked, plan.Warnings)
	}
	reasons := maskReasons(plan)
	_, hasEnv := reasons[".env"]
	_, local := reasons[".env.local"]
	_, aws := reasons["notes/aws.txt"]
	if !hasEnv || local || aws || reasons["config/prod.yaml"] != "pattern:config/prod.yaml" {
		t.Fatalf("masked = %v; want .env and the operator pattern, not the unmasked .env.local and notes/", reasons)
	}
	if m, ok := mountByTarget(plan, "/work/myapp/.aws"); !ok || !strings.HasSuffix(m.Source, "emptydir") {
		t.Fatalf(".aws/ must be a directory mask: %+v", m)
	}
	for _, m := range plan.Masked {
		if m.Rel == ".aws" && !m.Dir {
			t.Fatalf(".aws mask = %+v", m)
		}
	}
	if strings.Join(plan.Unmasked, ",") != ".env.local,notes/aws.txt" || strings.Join(plan.TrackedSecrets, ",") != "testdata/server.key" {
		t.Fatalf("Unmasked = %v, TrackedSecrets = %v", plan.Unmasked, plan.TrackedSecrets)
	}
	// Without the unmask the content detector finds the AWS key, unless the
	// content scan is off.
	if r := maskReasons(mustPlan(t, e, "s3", nil)); r["notes/aws.txt"] != "content:CS-SEC-AWS-KEY" {
		t.Fatalf("content detector missed notes/aws.txt: %v", r)
	}
	if r := maskReasons(mustPlan(t, e, "s4", func(o *MountOptions) { o.DisableContentScan = true })); r["notes/aws.txt"] != "" {
		t.Fatal("content scan ran although disabled")
	}
}

// TestPlanMountPinsGitStateAndAncestors: the hooks path, config includes,
// submodule git dirs and linked worktrees are bound read-only (missing
// ones are created so they can be bound, and removed on release). A bind
// follows the directory entry it was made on, and a directory that is not
// itself a mount point can be renamed with mounts below it, so every
// directory between the project and a protected or masked path is bound
// onto itself: otherwise the agent could rename .git/modules (or the
// folder of a masked .env) away and plant a replacement that host git
// reads, or that the next start of the sandbox masks while the secret sits
// unmasked under its new name.
func TestPlanMountPinsGitStateAndAncestors(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "config", "core.hooksPath", ".githooks")
	mustMkdir(t, filepath.Join(e.project, "tools", "git"))
	e.git(e.project, "config", "include.path", "../tools/git/project.inc")
	// A submodule named with a slash nests below .git/modules.
	for _, sub := range []string{"lib", "vendor/deep"} {
		dir := filepath.Join(e.project, ".git", "modules", filepath.FromSlash(sub))
		mustMkdir(t, filepath.Join(dir, "objects"))
		mustMkdir(t, filepath.Join(dir, "refs"))
		writeFile(t, dir, "HEAD", "ref: refs/heads/main\n")
		writeFile(t, dir, "config", "[core]\n")
	}
	e.git(e.project, "worktree", "add", "-q", filepath.Join(e.home, "code", "wt"))
	writeFile(t, e.project, "services/api/.env", "API_KEY=inert-marker\n")

	plan := mustPlan(t, e, "s1", nil)
	for _, rel := range []string{".githooks", "tools/git/project.inc", ".git/worktrees", ".git/modules/lib/config", ".git/modules/lib/hooks",
		".git/modules/lib/commondir", ".git/modules/vendor/deep/config"} {
		if m, ok := mountByTarget(plan, "/work/myapp/"+rel); !ok || !m.ReadOnly {
			t.Fatalf("missing read-only mount %s: %+v", rel, plan.Mounts)
		}
	}
	for _, rel := range []string{".git/modules/lib", ".git/modules", ".git/modules/vendor", "services", "services/api", "tools", "tools/git"} {
		if m, ok := mountByTarget(plan, "/work/myapp/"+rel); !ok || m.Kind != MountPin || m.ReadOnly || m.Source != filepath.Join(e.project, filepath.FromSlash(rel)) {
			t.Fatalf("%s is not pinned onto itself: %+v (found %v)", rel, m, ok)
		}
	}
	// Every mount inside the project sits in a directory that is mounted
	// itself, up to the project.
	for _, m := range plan.Mounts {
		if parent := path.Dir(m.Target); strings.HasPrefix(m.Target, plan.Target+"/") && parent != plan.Target {
			if _, ok := mountByTarget(plan, parent); !ok {
				t.Errorf("%s: its folder %s is not pinned", m.Target, parent)
			}
		}
	}
	created := []string{".githooks", "tools/git/project.inc", ".git/modules/lib/hooks", ".git/modules/lib/commondir"}
	for _, rel := range created {
		wantFiles(t, e.project, rel, present)
	}
	must(t, ReleaseMount(e.data, "s1"))
	for _, rel := range append(created, ".git/commondir") {
		wantFiles(t, e.project, rel, absent)
	}
	// Pins of existing directories create nothing, so release leaves them.
	wantFiles(t, e.project, ".git/modules/vendor/deep/config", present, "services/api/.env", present, "tools/git", present)
	wantFiles(t, e.data, "sandboxes/s1/workspace/mount.json", absent)
}

// markerDetector flags content holding an inert marker.
type markerDetector struct{}

func (markerDetector) DetectSecret(_ string, content []byte) (string, bool) {
	return "test-marker", strings.Contains(string(content), "inert-content-marker")
}

// TestPlanMountChecksTheTopOfHeavyDirectories: package caches, virtualenvs
// and tool state are not walked whole, but a credential file directly
// inside one is masked by name (Terraform keeps the backend configuration,
// credentials included, in .terraform/terraform.tfstate). Packages' own key
// and certificate files deeper down stay visible, contents there are not
// scanned, and an operator glob with a slash reaches as deep as it names.
func TestPlanMountChecksTheTopOfHeavyDirectories(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".terraform/terraform.tfstate", "{\"backend\":{\"config\":{\"access_key\":\"inert-marker\"}}}\n")
	writeFile(t, e.project, ".terraform/providers/registry/aws.key", "provider fixture\n")
	writeFile(t, e.project, ".cache/.env", "TOKEN=inert-marker\n")
	writeFile(t, e.project, ".cache/notes.txt", "inert-content-marker\n")
	writeFile(t, e.project, ".cache/hf/token", "inert-marker\n")
	writeFile(t, e.project, ".cache/hf/other.txt", "not a secret\n")
	writeFile(t, e.project, "node_modules/pkg/test/fixture.pem", "package fixture\n")
	writeFile(t, e.project, "node_modules/pkg/.env", "package file\n")
	writeFile(t, e.project, ".venv/lib/python3/site-packages/certifi/cacert.pem", "ca bundle\n")
	writeFile(t, e.project, "src/notes.txt", "inert-content-marker\n")

	plan := mustPlan(t, e, "s1", func(o *MountOptions) {
		o.Masks = []string{".cache/hf/token"}
		o.Detector = markerDetector{}
	})
	if got, want := strings.Join(plan.MaskedRels(), " "), ".cache/.env .cache/hf/token .terraform/terraform.tfstate src/notes.txt"; got != want {
		t.Fatalf("masked = %q, want %q", got, want)
	}
	for _, rel := range []string{".cache", ".cache/hf", ".terraform"} {
		if m, ok := mountByTarget(plan, "/work/myapp/"+rel); !ok || m.Kind != MountPin {
			t.Fatalf("%s holds a mask but is not pinned: %+v", rel, m)
		}
	}
}

func TestGlobsReachBelow(t *testing.T) {
	for _, c := range []struct {
		pattern, dir string
		want         bool
	}{
		{".cache/hf/token", ".cache", true},
		{".cache/hf/token", ".cache/hf", true},
		{".cache/hf/token", ".cache/hf/token", false},
		{".cache/*/token", ".cache/hf", true},
		{".cache/**/token", ".cache/a/b/c", true},
		{"/.CACHE/hf/", ".cache", true},
		{".cache/hf/token", "node_modules", false},
		{"sub/.cache/hf/token", ".cache", false},
		{"**/token", ".cache", false},
		{"token", ".cache", false},
		{"*.pem", "node_modules", false},
	} {
		if got := globsReachBelow([]string{c.pattern}, c.dir); got != c.want {
			t.Errorf("globsReachBelow(%q, %q) = %v, want %v", c.pattern, c.dir, got, c.want)
		}
	}
}

// TestReleaseMountKeepsPinsInUse: releasing a mount removes the pins it
// created and its state directory, but keeps a pin the operator filled
// meanwhile and one another sandbox still binds, and keeps every pin when
// another sandbox's state cannot be read.
func TestReleaseMountKeepsPinsInUse(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "config", "core.hooksPath", ".githooks")
	mustPlan(t, e, "s1", nil)
	lay, _ := newLayout(e.data)
	wantFiles(t, lay.workspaceDir("s1"), "mount.json", present)
	writeFile(t, e.project, ".githooks/pre-commit", "#!/bin/sh\n")
	must(t, ReleaseMount(e.data, "s1"))
	wantFiles(t, e.project, ".githooks/pre-commit", present, ".git/commondir", absent)
	wantFiles(t, lay.workspaceDir("s1"), "", absent)
	if err := ReleaseMount(e.data, "never-planned"); err != nil {
		t.Fatalf("releasing an unknown sandbox: %v", err)
	}

	e.git(e.project, "config", "--unset", "core.hooksPath")
	mustRemove(t, e.project, ".git/hooks")
	mustPlan(t, e, "first", nil)
	mustPlan(t, e, "second", nil)
	must(t, ReleaseMount(e.data, "first"))
	wantFiles(t, e.project, ".git/commondir", present, ".git/hooks", present)
	must(t, ReleaseMount(e.data, "second"))
	wantFiles(t, e.project, ".git/commondir", absent)

	mustPlan(t, e, "third", nil)
	writeFile(t, e.data, "sandboxes/broken/workspace/mount.json", "{not json")
	must(t, ReleaseMount(e.data, "third"))
	wantFiles(t, e.project, ".git/commondir", present)
}

// TestPlanMountContextFolders: context folders are mounted read-only with
// their secrets masked; the project, a folder inside it, the home folder
// and a bad name are refused, and a refused plan removes the git pins it
// had created.
func TestPlanMountContextFolders(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	lib := filepath.Join(e.home, "code", "lib")
	writeFile(t, lib, "lib.go", "package lib\n")
	writeFile(t, lib, ".env", "K=1\n")
	other := filepath.Join(e.root, "elsewhere", "myapp")
	writeFile(t, other, "x.txt", "x")

	plan := mustPlan(t, e, "s1", func(o *MountOptions) { o.Context = []string{lib, other} })
	if len(plan.Contexts) != 2 || plan.Contexts[0].Target != "/work/lib" || plan.Contexts[1].Target != "/work/myapp-2" ||
		strings.Join(plan.ReadOnly, ",") != "/work/lib,/work/myapp-2" {
		t.Fatalf("contexts = %+v, ReadOnly = %v", plan.Contexts, plan.ReadOnly)
	}
	if m, ok := mountByTarget(plan, "/work/lib"); !ok || !m.ReadOnly || m.Kind != MountContext {
		t.Fatalf("context mount = %+v", m)
	}
	if m, ok := mountByTarget(plan, "/work/lib/.env"); !ok || m.Kind != MountMask {
		t.Fatalf("context secrets must be masked too: %+v", plan.Mounts)
	}
	must(t, ReleaseMount(e.data, "s1"))

	mustMkdir(t, filepath.Join(e.project, "sub"))
	for _, bad := range [][]string{{e.project}, {filepath.Join(e.project, "sub")}, {e.home}} {
		opts := e.mountOpts("s2")
		opts.Context = bad
		if _, err := PlanMount(bg, opts); !errors.Is(err, ErrUnsafeSource) {
			t.Fatalf("context %v: err = %v, want ErrUnsafeSource", bad, err)
		}
		wantFiles(t, e.project, ".git/commondir", absent)
	}
	if _, err := PlanMount(bg, MountOptions{Project: e.home, Name: "s1", DataDir: e.data, Home: e.home}); !errors.Is(err, ErrUnsafeSource) {
		t.Fatalf("home: %v", err)
	}
	if _, err := PlanMount(bg, e.mountOpts("../x")); err == nil {
		t.Fatal("bad name accepted")
	}
}

// TestPlanMountRefusesAFolderTheScanCannotFinish: past the walk limit no
// file would be masked, so the mount is refused instead of starting with
// a warning, and nothing is left behind.
func TestPlanMountRefusesAFolderTheScanCannotFinish(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	for i := 0; i < 8; i++ {
		writeFile(t, e.project, fmt.Sprintf("pkg%d/file.go", i), "package p\n")
	}
	writeFile(t, e.project, "zz/.env", "TOKEN=marker\n")
	opts := e.mountOpts("s1")
	opts.MaxWalkEntries = 6
	_, err := PlanMount(bg, opts)
	var incomplete *ScanIncompleteError
	if !errors.As(err, &incomplete) || !errors.Is(err, ErrScanIncomplete) || !incomplete.Git || incomplete.Limit != 6 || !strings.Contains(err.Error(), "--copy") {
		t.Fatalf("err = %v, want a *ScanIncompleteError for a git project that names copy mode", err)
	}
	wantFiles(t, e.data, "sandboxes/s1/workspace/mount.json", absent)
	wantFiles(t, e.project, ".git/commondir", absent)

	// Context folders are held to the same rule (the project itself now
	// fits: about half a dozen entries).
	for i := 0; i < 8; i++ {
		mustRemove(t, e.project, fmt.Sprintf("pkg%d", i))
	}
	lib := filepath.Join(e.home, "code", "lib")
	for i := 0; i < 8; i++ {
		writeFile(t, lib, fmt.Sprintf("d%d/x.txt", i), "x\n")
	}
	opts = e.mountOpts("s2")
	opts.Context = []string{lib}
	opts.MaxWalkEntries = 30
	if _, err := PlanMount(bg, opts); err != nil {
		t.Fatalf("folders within the limit: %v", err)
	}
	opts.Name, opts.MaxWalkEntries = "s3", 12
	if _, err := PlanMount(bg, opts); !errors.As(err, &incomplete) || incomplete.Path != lib || incomplete.Git {
		t.Fatalf("context folder past the limit: %v", err)
	}
}
