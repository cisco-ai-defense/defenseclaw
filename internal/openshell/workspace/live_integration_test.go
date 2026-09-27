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

//go:build openshell_integration && (linux || darwin)

package workspace

// Live checks against a local OpenShell 0.1.x gateway with bind mounts
// enabled (FINDINGS-core §10):
//
//	go test -tags openshell_integration -run TestLive -v ./internal/openshell/workspace/
//
// DEFENSECLAW_OPENSHELL_IMAGE overrides the sandbox image (default: the
// digest-pinned community base) and DEFENSECLAW_OPENSHELL_GATEWAY the
// gateway registration. Sandboxes are named f1-live-* and deleted at the
// end.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

type liveSandbox struct {
	t    *testing.T
	cli  *CLI
	name string
}

func liveCLI(t *testing.T) *CLI {
	if _, err := runProcessOK("openshell", "--version"); err != nil {
		t.Skip("openshell CLI not available: ", err)
	}
	gw := os.Getenv("DEFENSECLAW_OPENSHELL_GATEWAY")
	if gw == "" {
		gw = "openshell"
	}
	return &CLI{Gateway: gw, ExecTimeout: 90 * time.Second}
}

// liveArgv is `openshell <verbs> -g <gateway> --workspace <ws>` for the
// sandbox create and delete calls CLI does not wrap.
func liveArgv(cli *CLI, verbs ...string) []string {
	bin, ws := cli.Binary, cli.Workspace
	if bin == "" {
		bin = openshell.DefaultBinary
	}
	if ws == "" {
		ws = openshell.DefaultWorkspace
	}
	return append(append([]string{bin}, verbs...), "-g", cli.Gateway, "--workspace", ws)
}

func runProcessOK(argv ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var stdout strings.Builder
	stderr, code, err := runProcess(ctx, argv, &stdout)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("%s: exit %d: %s", strings.Join(argv[:2], " "), code, lastLines(stderr, 8))
	}
	return stdout.String(), nil
}

func liveImage() string {
	if img := os.Getenv("DEFENSECLAW_OPENSHELL_IMAGE"); img != "" {
		return img
	}
	return openshell.DefaultBaseImage
}

// createLive creates a sandbox with the given policy and optional mounts.
func createLive(t *testing.T, cli *CLI, name, policy string, driverConfig string, labels map[string]string) *liveSandbox {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	argv := liveArgv(cli, "sandbox", "create")
	argv = append(argv, "--name", name, "--from", liveImage(), "--policy", policyPath,
		"--detach", "--no-auto-providers", "-o", "json")
	if driverConfig != "" {
		argv = append(argv, "--driver-config-json", driverConfig)
	}
	for k, v := range labels {
		argv = append(argv, "--label", k+"="+v)
	}
	sb := &liveSandbox{t: t, cli: cli, name: name}
	t.Cleanup(sb.delete)
	out, err := runProcessOK(argv...)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	var created struct {
		Phase string `json:"phase"`
	}
	_ = json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &created)
	t.Logf("created %s (phase %s)", name, created.Phase)
	// FINDINGS-harness P1: in-flight connections drop ~10-15 s after start.
	time.Sleep(15 * time.Second)
	return sb
}

func (s *liveSandbox) delete() {
	argv := liveArgv(s.cli, "sandbox", "delete")
	if _, err := runProcessOK(append(argv, s.name)...); err != nil {
		s.t.Logf("delete %s: %v", s.name, err)
	}
}

// sh runs a shell snippet in the sandbox and returns stdout, stderr and the
// exit code.
func (s *liveSandbox) sh(script string) (string, string, int) {
	s.t.Helper()
	res, err := s.cli.Exec(context.Background(), s.name, ExecRequest{Argv: []string{"sh", "-c", script}})
	if err != nil {
		s.t.Fatalf("exec %q: %v", script, err)
	}
	return string(res.Stdout), string(res.Stderr), res.ExitCode
}

func mountPolicy(plan *MountPlan) string {
	rw := append([]string{"/tmp", "/dev/null"}, plan.ReadWrite...)
	ro := append([]string{"/usr", "/lib", "/etc", "/proc", "/dev/urandom", "/var/log", "/opt"}, plan.ReadOnly...)
	return fmt.Sprintf(`version: 1
filesystem_policy:
  include_workdir: true
  read_only: [%s]
  read_write: [%s]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: %q
  run_as_group: %q
network_policies: {}
`, strings.Join(ro, ", "), strings.Join(rw, ", "), plan.RunAsUser, plan.RunAsGroup)
}

func liveEnv(t *testing.T) *env {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, root: root, home: filepath.Join(root, "home")}
	e.data = filepath.Join(e.home, ".defenseclaw")
	e.project = filepath.Join(e.home, "code", "myapp")
	mustMkdir(t, e.project)
	mustMkdir(t, e.data)
	return e
}

func TestLiveMountPlanMasksAndProtects(t *testing.T) {
	cli := liveCLI(t)
	e := liveEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".env", "API_KEY=live-secret\n")
	writeFile(t, e.project, "certs/dev.pem", "-----fake-----\n")
	name := fmt.Sprintf("f1-live-mount-%d", time.Now().Unix()%100000)

	plan, err := PlanMount(bg, e.mountOpts(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ReleaseMount(e.data, name) })
	for _, l := range plan.Summary().Lines() {
		t.Log(l)
	}
	if _, err := Snapshot(bg, e.snapOpts(name)); err != nil {
		t.Fatal(err)
	}
	dc, err := plan.DriverConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	sb := createLive(t, cli, name, mountPolicy(plan), dc, plan.Labels)
	w := plan.Target

	checks := []struct {
		name, script string
		wantCode     int // -1: any non-zero
		wantOut      string
	}{
		{"runs as the host uid", "id -u", 0, plan.RunAsUser},
		{".env is masked", "wc -c < " + w + "/.env", 0, "0"},
		{"pem is masked", "cat " + w + "/certs/dev.pem | wc -c", 0, "0"},
		{"mask cannot be removed", "rm -f " + w + "/.env", -1, ""},
		{"hooks are read-only", "echo 'exit 0' > " + w + "/.git/hooks/pre-commit", -1, ""},
		{"config is read-only", "git -C " + w + " config user.name agent", -1, ""},
		{"git dir cannot be renamed", "mv " + w + "/.git " + w + "/.git-old", -1, ""},
		{"commondir pin holds", "echo ../evil > " + w + "/.git/commondir", -1, ""},
		{"git works inside", "git -C " + w + " -c user.name=a -c user.email=a@a commit -q --allow-empty -m agent && git -C " + w + " log --oneline | wc -l", 0, "2"},
		{"project is writable", "echo agent > " + w + "/README.md && echo '{\"scripts\":{\"postinstall\":\"x\"}}' > " + w + "/package.json && echo ok", 0, "ok"},
		{"the host home is not visible", "test -e " + e.home, -1, ""},
		{"host credentials are not visible", "test -e " + os.Getenv("HOME") + "/.ssh", -1, ""},
	}
	for _, c := range checks {
		out, stderr, code := sb.sh(c.script)
		t.Logf("%-28s code=%d out=%q err=%q", c.name, code, strings.TrimSpace(out), strings.TrimSpace(lastLines([]byte(stderr), 2)))
		if c.wantCode == -1 && code == 0 {
			t.Errorf("%s: expected failure", c.name)
		}
		if c.wantCode >= 0 && code != c.wantCode {
			t.Errorf("%s: exit %d, want %d (%s)", c.name, code, c.wantCode, stderr)
		}
		if c.wantOut != "" && strings.TrimSpace(out) != c.wantOut {
			t.Errorf("%s: output %q, want %q", c.name, strings.TrimSpace(out), c.wantOut)
		}
	}
	if readFile(t, e.project, ".env") != "API_KEY=live-secret\n" {
		t.Fatal("host secret changed")
	}
	if readFile(t, e.project, "README.md") != "agent\n" {
		t.Fatal("live edit not visible on the host")
	}
	if info, err := os.Stat(filepath.Join(e.project, "README.md")); err == nil {
		if uid, _ := ownerUID(info); fmt.Sprint(uid) != plan.RunAsUser {
			t.Errorf("file written by the agent is owned by uid %d", uid)
		}
	}
	sb.delete()

	rep, err := Review(bg, ReviewOptions{DataDir: e.data, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rep.SummaryLine())
	t.Log(rep.RiskLine())
	if _, ok := flagByLabel(rep, "package.json#scripts.postinstall"); !ok {
		t.Errorf("review missed the postinstall script: %+v", rep.Flags)
	}
	res, err := Undo(bg, UndoOptions{DataDir: e.data, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("undo: %d changes, head %s -> %s", len(res.Changes), shortOID(res.HeadAfter), shortOID(res.HeadBefore))
	if readFile(t, e.project, "README.md") != "hello\n" || pathExists(filepath.Join(e.project, "package.json")) {
		t.Fatal("undo did not restore the folder")
	}
	if e.git(e.project, "rev-list", "--count", "HEAD") != "1" {
		t.Fatal("undo did not move the branch back")
	}
	if err := ReleaseMount(e.data, name); err != nil {
		t.Fatal(err)
	}
	if pathExists(filepath.Join(e.project, ".git", "commondir")) {
		t.Fatal("commondir pin not released")
	}
}

func TestLiveCopyRoundTrip(t *testing.T) {
	cli := liveCLI(t)
	e := liveEnv(t)
	e.initRepo()
	writeFile(t, e.project, "wip.txt", "operator wip\n")
	writeFile(t, e.project, "certs/dev.pem", "held back\n")
	name := fmt.Sprintf("f1-live-copy-%d", time.Now().Unix()%100000)
	t.Cleanup(func() { _ = DeleteCopy(e.data, name) })

	rec, err := Stage(bg, StageOptions{Project: e.project, Name: name, DataDir: e.data, Home: e.home})
	if err != nil {
		t.Fatal(err)
	}
	policy := fmt.Sprintf(`version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc, /proc, /dev/urandom, /var/log, /opt]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: %q
  run_as_group: %q
network_policies: {}
`, fmt.Sprint(os.Getuid()), fmt.Sprint(os.Getgid()))
	sb := createLive(t, cli, name, policy, "", rec.Labels())
	if _, err := Upload(bg, e.data, name, cli); err != nil {
		t.Fatal(err)
	}
	if _, err := EstablishBaseline(bg, e.data, name, cli); err != nil {
		t.Fatal(err)
	}
	w := rec.RemoteDir
	out, stderr, code := sb.sh("cd " + w + " && test ! -e certs/dev.pem && cat wip.txt && " +
		"echo 'package main // agent' > src/app.go && git -c user.name=a -c user.email=a@a commit -q -am agent && echo new > agent.txt && git status --porcelain")
	t.Logf("agent: code=%d out=%q err=%q", code, out, lastLines([]byte(stderr), 3))
	if code != 0 {
		t.Fatalf("agent script failed: %s", stderr)
	}
	writeFile(t, e.project, "README.md", "host edit during the session\n")

	pr, err := Pull(bg, PullOptions{DataDir: e.data, Name: name, Exec: cli})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pull: %s, blocking=%v", changePaths(pr.Changes), pr.Blocking)
	if got := changePaths(pr.Changes); got != "A:agent.txt M:src/app.go" {
		t.Fatalf("changes = %s", got)
	}
	res, err := Apply(bg, ApplyOptions{DataDir: e.data, Name: name, Mode: ApplyMerge})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || readFile(t, e.project, "src/app.go") != "package main // agent\n" || readFile(t, e.project, "agent.txt") != "new\n" ||
		readFile(t, e.project, "README.md") != "host edit during the session\n" || readFile(t, e.project, "certs/dev.pem") != "held back\n" {
		t.Fatalf("apply: %+v", res)
	}
}

// TestLiveCopyPlainFolder runs a non-git folder through copy mode: the
// hidden git dir lands outside the folder (/sandbox/.dc/git), the agent's
// edits come back, and the folder in the sandbox never gets a .git.
func TestLiveCopyPlainFolder(t *testing.T) {
	cli := liveCLI(t)
	e := liveEnv(t)
	writeFile(t, e.project, "notes.md", "operator notes\n")
	writeFile(t, e.project, ".env", "DCE2E_PLACEHOLDER=not-a-secret\n")
	name := fmt.Sprintf("f1-live-plain-%d", time.Now().Unix()%100000)
	t.Cleanup(func() { _ = DeleteCopy(e.data, name) })

	rec, err := Stage(bg, StageOptions{Project: e.project, Name: name, DataDir: e.data, Home: e.home})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != CopyPlain {
		t.Fatalf("kind = %s, want plain", rec.Kind)
	}
	policy := fmt.Sprintf(`version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc, /proc, /dev/urandom, /var/log, /opt]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: %q
  run_as_group: %q
network_policies: {}
`, fmt.Sprint(os.Getuid()), fmt.Sprint(os.Getgid()))
	sb := createLive(t, cli, name, policy, "", rec.Labels())
	if _, err := Upload(bg, e.data, name, cli); err != nil {
		t.Fatal(err)
	}
	if _, err := EstablishBaseline(bg, e.data, name, cli); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := sb.sh("cd " + rec.RemoteDir + " && test ! -e .git && test ! -e .env && cat notes.md && echo agent >> notes.md && echo new > added.txt")
	t.Logf("agent: code=%d out=%q err=%q", code, out, lastLines([]byte(stderr), 3))
	if code != 0 || out != "operator notes\n" {
		t.Fatalf("agent script failed: %s", stderr)
	}
	pr, err := Pull(bg, PullOptions{DataDir: e.data, Name: name, Exec: cli})
	if err != nil {
		t.Fatal(err)
	}
	if got := changePaths(pr.Changes); got != "A:added.txt M:notes.md" {
		t.Fatalf("changes = %s", got)
	}
	res, err := Apply(bg, ApplyOptions{DataDir: e.data, Name: name, Mode: ApplyMerge})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || readFile(t, e.project, "notes.md") != "operator notes\nagent\n" || readFile(t, e.project, "added.txt") != "new\n" ||
		readFile(t, e.project, ".env") != "DCE2E_PLACEHOLDER=not-a-secret\n" || pathExists(filepath.Join(e.project, ".git")) {
		t.Fatalf("apply: %+v", res)
	}
}
