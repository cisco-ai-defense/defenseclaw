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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestPlanMountGitRepoProtectsHostExecutableState(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".env", "API_KEY=abc\n")
	writeFile(t, e.project, "certs/dev.pem", "not really a key\n")
	writeFile(t, e.project, ".env.example", "API_KEY=\n")

	plan, err := PlanMount(bg, e.mountOpts("dc-claude-myapp-7f3a"))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Target != "/work/myapp" || plan.Project != e.project || plan.RepoName != "myapp" {
		t.Fatalf("plan identity: %+v", plan)
	}
	if plan.RunAsUser != strconv.Itoa(os.Getuid()) || plan.RunAsGroup != strconv.Itoa(os.Getgid()) {
		t.Fatalf("run-as %s:%s", plan.RunAsUser, plan.RunAsGroup)
	}
	if len(plan.ReadWrite) != 1 || plan.ReadWrite[0] != "/work/myapp" {
		t.Fatalf("ReadWrite = %v", plan.ReadWrite)
	}
	if plan.Labels[ProjectLabelKey] != ProjectKey(e.project) || plan.Labels[ModeLabelKey] != "mount" {
		t.Fatalf("labels = %v", plan.Labels)
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
	}
	for target, w := range want {
		m, ok := mountByTarget(plan, target)
		if !ok {
			t.Fatalf("missing mount %s in %+v", target, plan.Mounts)
		}
		if m.Kind != w.kind || m.ReadOnly != w.ro {
			t.Fatalf("%s = %+v, want kind %s ro %v", target, m, w.kind, w.ro)
		}
	}
	if _, ok := mountByTarget(plan, "/work/myapp/.env.example"); ok {
		t.Fatal(".env.example is a template and must stay visible")
	}
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
	if got := readFile(t, e.project, ".git/commondir"); got != commondirPin {
		t.Fatalf("commondir pin = %q", got)
	}
	if out := e.git(e.project, "status", "--porcelain"); strings.Contains(out, "fatal") {
		t.Fatalf("git broke with the pin: %s", out)
	}
	// Masks bind an empty, read-only file owned by the operator.
	m, _ := mountByTarget(plan, "/work/myapp/.env")
	info, err := os.Stat(m.Source)
	if err != nil || info.Size() != 0 || info.Mode().Perm() != 0o444 || !strings.HasPrefix(m.Source, e.data) {
		t.Fatalf("mask source %s: %v %v", m.Source, info, err)
	}

	lines := strings.Join(plan.Summary().Lines(), "\n")
	for _, s := range []string{"~/code/myapp → /work/myapp (live)", ".env", "certs/dev.pem", "--unmask", ".git/hooks", ".git/config", ".git/config.worktree", "(read-only)", "Not visible"} {
		if !strings.Contains(lines, s) {
			t.Fatalf("banner missing %q:\n%s", s, lines)
		}
	}
}

func TestPlanMountDriverConfigIsStructpbCompatible(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	plan, err := PlanMount(bg, e.mountOpts("s1"))
	if err != nil {
		t.Fatal(err)
	}
	dc := plan.DriverConfig()
	if _, err := structpb.NewStruct(dc); err != nil {
		t.Fatalf("DriverConfig is not structpb-compatible: %v", err)
	}
	raw, err := plan.DriverConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Docker struct {
			Mounts []struct {
				Type     string `json:"type"`
				Source   string `json:"source"`
				Target   string `json:"target"`
				ReadOnly bool   `json:"read_only"`
			} `json:"mounts"`
		} `json:"docker"`
	}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Docker.Mounts) != len(plan.Mounts) || decoded.Docker.Mounts[0].Type != "bind" ||
		decoded.Docker.Mounts[0].Target != "/work/myapp" || decoded.Docker.Mounts[0].ReadOnly {
		t.Fatalf("driver config = %s", raw)
	}
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

	plan, err := PlanMount(bg, e.mountOpts("s1"))
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, m := range plan.Masked {
		reasons[m.Rel] = m.Reason
	}
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
	if strings.Join(plan.TrackedSecrets, ",") != "testdata/server.key" {
		t.Fatalf("TrackedSecrets = %v", plan.TrackedSecrets)
	}
	if !strings.Contains(strings.Join(plan.Warnings, "\n"), "hold exactly their committed contents") {
		t.Fatalf("warnings = %v", plan.Warnings)
	}

	opts := e.mountOpts("s2")
	opts.MaskTracked = true
	if plan, err = PlanMount(bg, opts); err != nil {
		t.Fatal(err)
	}
	if len(plan.TrackedSecrets) != 0 {
		t.Fatalf("MaskTracked left %v visible", plan.TrackedSecrets)
	}
}

func TestTrackedEntryHolds(t *testing.T) {
	for _, tc := range []struct {
		e    trackedEntry
		data string
		want bool
	}{
		{trackedEntry{mode: "100644", oid: "5abed26af8585d58b8923135234ca8d1d77128b4"}, "marker\n", true},
		{trackedEntry{mode: "100755", oid: "5abed26af8585d58b8923135234ca8d1d77128b4"}, "marker\n", true},
		{trackedEntry{mode: "100644", oid: "52c2fcd945b8573594a0976f8a75079d8c0a3e0b2c03f7f50eb46cf94067c8bb"}, "marker\n", true},
		{trackedEntry{mode: "100644", oid: "5abed26af8585d58b8923135234ca8d1d77128b4"}, "marker!\n", false},
		{trackedEntry{mode: "120000", oid: "5abed26af8585d58b8923135234ca8d1d77128b4"}, "marker\n", false},
		{trackedEntry{mode: "100644", oid: "5abed26a"}, "marker\n", false},
	} {
		if got := tc.e.holds([]byte(tc.data)); got != tc.want {
			t.Errorf("%+v holds %q = %v, want %v", tc.e, tc.data, got, tc.want)
		}
	}
}

func TestDetectSecretsBoundsTrackedComparisons(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.txt", "one\n")
	writeFile(t, root, "b.txt", "two\n")
	tracked := map[string]trackedEntry{
		"a.txt": {mode: "100644", oid: strings.Repeat("0", 40), watched: true},
		"b.txt": {mode: "100644", oid: strings.Repeat("0", 40), watched: true},
	}
	scan, err := detectSecrets(root, secretScanOptions{tracked: tracked, contentScan: true, detector: DefaultSecretDetector(), maxTrackedReads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(scan.warnings, "\n"), "1 tracked file(s) past the first 1") {
		t.Fatalf("warnings = %v", scan.warnings)
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
	mustMkdir(t, filepath.Join(e.project, ".aws"))
	writeFile(t, e.project, ".aws/credentials", "[default]\n")
	writeFile(t, e.project, "config/prod.yaml", "db: secret\n")

	opts := e.mountOpts("s2")
	opts.Unmask = []string{".env.local", filepath.Join(e.project, "notes")}
	opts.Masks = []string{"config/prod.yaml"}
	plan, err := PlanMount(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]MaskedPath{}
	for _, m := range plan.Masked {
		got[m.Rel] = m
	}
	if _, ok := got[".env"]; !ok {
		t.Fatalf("masked = %+v, want .env", plan.Masked)
	}
	if m, ok := got[".aws"]; !ok || !m.Dir {
		t.Fatalf("masked = %+v, want .aws/ as a directory mask", plan.Masked)
	}
	if m, ok := got["config/prod.yaml"]; !ok || m.Reason != "pattern:config/prod.yaml" {
		t.Fatalf("masked = %+v, want operator pattern", plan.Masked)
	}
	if _, ok := got[".env.local"]; ok {
		t.Fatal("--unmask .env.local was ignored")
	}
	if _, ok := got["notes/aws.txt"]; ok {
		t.Fatal("--unmask of an absolute directory was ignored")
	}
	if strings.Join(plan.Unmasked, ",") != ".env.local,notes/aws.txt" {
		t.Fatalf("Unmasked = %v", plan.Unmasked)
	}
	if len(plan.TrackedSecrets) != 1 || plan.TrackedSecrets[0] != "testdata/server.key" {
		t.Fatalf("TrackedSecrets = %v", plan.TrackedSecrets)
	}
	m, _ := mountByTarget(plan, "/work/myapp/.aws")
	if !strings.HasSuffix(m.Source, "emptydir") {
		t.Fatalf("directory mask source = %s", m.Source)
	}

	// Without the unmask the content detector finds the AWS key.
	opts.Unmask = nil
	opts.Name = "s3"
	plan, err = PlanMount(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range plan.Masked {
		if m.Rel == "notes/aws.txt" && m.Reason == "content:CS-SEC-AWS-KEY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("content detector missed notes/aws.txt: %+v", plan.Masked)
	}
	opts.DisableContentScan = true
	opts.Name = "s4"
	plan, err = PlanMount(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range plan.Masked {
		if m.Rel == "notes/aws.txt" {
			t.Fatal("content scan ran although disabled")
		}
	}
}

func TestPlanMountHardlinkedSecretWarns(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(e.home, "outside-secret")
	if err := os.WriteFile(outside, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(e.project, ".env")); err != nil {
		t.Skip("hard links unavailable")
	}
	plan, err := PlanMount(bg, e.mountOpts("s1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Masked) != 1 || !plan.Masked[0].Hardlinked {
		t.Fatalf("masked = %+v", plan.Masked)
	}
	if !strings.Contains(strings.Join(plan.Warnings, "\n"), "hard links") {
		t.Fatalf("warnings = %v", plan.Warnings)
	}
}

func TestPlanMountHooksPathIncludesSubmodulesAndWorktrees(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "config", "core.hooksPath", ".githooks")
	e.git(e.project, "config", "include.path", "../.gitconfig.project")
	mustMkdir(t, filepath.Join(e.project, ".git", "modules", "lib", "objects"))
	mustMkdir(t, filepath.Join(e.project, ".git", "modules", "lib", "refs"))
	writeFile(t, e.project, ".git/modules/lib/HEAD", "ref: refs/heads/main\n")
	writeFile(t, e.project, ".git/modules/lib/config", "[core]\n")
	e.git(e.project, "worktree", "add", "-q", filepath.Join(e.home, "code", "wt"))

	plan, err := PlanMount(bg, e.mountOpts("s1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/work/myapp/.githooks", "/work/myapp/.gitconfig.project", "/work/myapp/.git/worktrees",
		"/work/myapp/.git/modules/lib/config", "/work/myapp/.git/modules/lib/hooks", "/work/myapp/.git/modules/lib/commondir",
	} {
		m, ok := mountByTarget(plan, target)
		if !ok || !m.ReadOnly {
			t.Fatalf("missing read-only mount %s: %+v", target, plan.Mounts)
		}
	}
	if m, ok := mountByTarget(plan, "/work/myapp/.git/modules/lib"); !ok || m.Kind != MountPin || m.ReadOnly {
		t.Fatalf("submodule git dir is not pinned: %+v", m)
	}
	// Missing pins were created so they could be bound.
	for _, p := range []string{".githooks", ".gitconfig.project", ".git/modules/lib/hooks", ".git/modules/lib/commondir"} {
		if !pathExists(filepath.Join(e.project, p)) {
			t.Fatalf("pin %s was not created", p)
		}
	}
	if err := ReleaseMount(e.data, "s1"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".githooks", ".gitconfig.project", ".git/commondir", ".git/modules/lib/commondir", ".git/modules/lib/hooks"} {
		if pathExists(filepath.Join(e.project, p)) {
			t.Fatalf("ReleaseMount left %s behind", p)
		}
	}
	if pathExists(filepath.Join(e.data, "sandboxes", "s1", "workspace", "mount.json")) {
		t.Fatal("mount state not removed")
	}
}

func TestReleaseMountKeepsPinsTheOperatorChanged(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "config", "core.hooksPath", ".githooks")
	if _, err := PlanMount(bg, e.mountOpts("s1")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.project, ".githooks/pre-commit", "#!/bin/sh\n")
	if err := ReleaseMount(e.data, "s1"); err != nil {
		t.Fatal(err)
	}
	if !pathExists(filepath.Join(e.project, ".githooks", "pre-commit")) {
		t.Fatal("release removed a hooks directory the operator filled")
	}
	if pathExists(filepath.Join(e.project, ".git", "commondir")) {
		t.Fatal("unchanged commondir pin should be released")
	}
	if err := ReleaseMount(e.data, "never-planned"); err != nil {
		t.Fatalf("releasing an unknown sandbox: %v", err)
	}
}

func TestReleaseMountKeepsPinsAnotherSandboxBinds(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	if err := os.RemoveAll(filepath.Join(e.project, ".git", "hooks")); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanMount(bg, e.mountOpts("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanMount(bg, e.mountOpts("second")); err != nil {
		t.Fatal(err)
	}
	if err := ReleaseMount(e.data, "first"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".git/commondir", ".git/hooks"} {
		if !pathExists(filepath.Join(e.project, p)) {
			t.Fatalf("%s removed while the second sandbox still binds it", p)
		}
	}
	if err := ReleaseMount(e.data, "second"); err != nil {
		t.Fatal(err)
	}
	if pathExists(filepath.Join(e.project, ".git", "commondir")) {
		t.Fatal("last release must remove the commondir pin")
	}
	// A corrupt state of some other sandbox makes release conservative.
	if _, err := PlanMount(bg, e.mountOpts("third")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.data, "sandboxes/broken/workspace/mount.json", "{not json")
	if err := ReleaseMount(e.data, "third"); err != nil {
		t.Fatal(err)
	}
	if !pathExists(filepath.Join(e.project, ".git", "commondir")) {
		t.Fatal("release with an unreadable peer state must keep pins")
	}
}

func TestPlanMountContextFolders(t *testing.T) {
	e := newEnv(t)
	lib := filepath.Join(e.home, "code", "lib")
	writeFile(t, lib, "lib.go", "package lib\n")
	writeFile(t, lib, ".env", "K=1\n")
	other := filepath.Join(e.root, "elsewhere", "myapp")
	writeFile(t, other, "x.txt", "x")

	opts := e.mountOpts("s1")
	opts.Context = []string{lib, other}
	plan, err := PlanMount(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Contexts) != 2 || plan.Contexts[0].Target != "/work/lib" || plan.Contexts[1].Target != "/work/myapp-2" {
		t.Fatalf("contexts = %+v", plan.Contexts)
	}
	if m, ok := mountByTarget(plan, "/work/lib"); !ok || !m.ReadOnly || m.Kind != MountContext {
		t.Fatalf("context mount = %+v", m)
	}
	if m, ok := mountByTarget(plan, "/work/lib/.env"); !ok || m.Kind != MountMask {
		t.Fatalf("context secrets must be masked too: %+v", plan.Mounts)
	}
	if strings.Join(plan.ReadOnly, ",") != "/work/lib,/work/myapp-2" {
		t.Fatalf("ReadOnly = %v", plan.ReadOnly)
	}

	for _, bad := range [][]string{{e.project}, {filepath.Join(e.project, "sub")}, {e.home}} {
		mustMkdir(t, filepath.Join(e.project, "sub"))
		opts.Context = bad
		opts.Name = "s2"
		if _, err := PlanMount(bg, opts); !errors.Is(err, ErrUnsafeSource) {
			t.Fatalf("context %v: err = %v, want ErrUnsafeSource", bad, err)
		}
	}
}

func TestPlanMountRefusesAndRollsBack(t *testing.T) {
	e := newEnv(t)
	if _, err := PlanMount(bg, MountOptions{Project: e.home, Name: "s1", DataDir: e.data, Home: e.home}); !errors.Is(err, ErrUnsafeSource) {
		t.Fatalf("home: %v", err)
	}
	if _, err := PlanMount(bg, MountOptions{Project: e.project, Name: "../x", DataDir: e.data, Home: e.home}); err == nil {
		t.Fatal("bad name accepted")
	}
	// A context failure after git pins were created must remove them.
	e.initRepo()
	opts := e.mountOpts("s1")
	opts.Context = []string{e.home}
	if _, err := PlanMount(bg, opts); err == nil {
		t.Fatal("expected failure")
	}
	if pathExists(filepath.Join(e.project, ".git", "commondir")) {
		t.Fatal("failed plan left its commondir pin behind")
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
	if !errors.As(err, &incomplete) || !errors.Is(err, ErrScanIncomplete) || !incomplete.Git || incomplete.Limit != 6 {
		t.Fatalf("err = %v, want a *ScanIncompleteError for a git project", err)
	}
	if !strings.Contains(err.Error(), "--copy") {
		t.Fatalf("the refusal does not name copy mode: %v", err)
	}
	if pathExists(filepath.Join(e.data, "sandboxes", "s1", "workspace", "mount.json")) || pathExists(filepath.Join(e.project, ".git", "commondir")) {
		t.Fatal("a refused plan left state behind")
	}

	// Context folders are held to the same rule (the project itself now
	// fits: about half a dozen entries).
	for i := 0; i < 8; i++ {
		if err := os.RemoveAll(filepath.Join(e.project, fmt.Sprintf("pkg%d", i))); err != nil {
			t.Fatal(err)
		}
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
