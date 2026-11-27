// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// gap0795 is a separated relay (this root test) and an agent of UID 65534
// with a checkout pushed to a local origin read as an https address.
type gap0795 struct {
	t                  *testing.T
	base, origin, repo string
	parent             string // the relay's scratch parent
	wrap               string
}

const (
	gap0795UID    = 65534
	gap0795Origin = "https://git.example.test/team/app.git"
)

func newGAP0795(t *testing.T) *gap0795 {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("GAP-0795: needs root (the separated relay) and an agent UID; run as root on a build box")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base, err := os.MkdirTemp("/tmp", "gap0795-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", "/tmp")
	g := &gap0795{t: t, base: base, origin: filepath.Join(base, "origin.git"), repo: filepath.Join(base, "work", "app"), parent: filepath.Join(base, "relay")}
	if err := os.Mkdir(g.parent, 0o755); err != nil {
		t.Fatal(err)
	}
	// upload-pack of a local origin owned by another user reads
	// safe.directory from the global config only.
	gc := filepath.Join(base, "gitconfig")
	if err := os.WriteFile(gc, []byte("[safe]\n\tdirectory = *\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.wrap = fmt.Sprintf("git() { GIT_CONFIG_GLOBAL=%s GIT_ALLOW_PROTOCOL=https:file command git -c 'url.file://%s.insteadOf=%s' \"$@\"; }\n", gc, g.origin, gap0795Origin)
	g.git(base, "init", "-q", "--bare", g.origin)
	g.git(base, "init", "-q", "-b", "main", g.repo)
	g.write("README", "one\n")
	g.git(g.repo, "add", ".")
	g.git(g.repo, "commit", "-qm", "base")
	g.git(g.repo, "push", "-q", g.origin, "HEAD:refs/heads/main")
	return g
}

func (g *gap0795) git(dir string, args ...string) string {
	g.t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "safe.directory=*"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		g.t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (g *gap0795) write(name, content string) {
	g.t.Helper()
	if err := os.WriteFile(filepath.Join(g.repo, name), []byte(content), 0o644); err != nil {
		g.t.Fatal(err)
	}
}

// handOver gives the checkout to the agent's user and lets it read origin.
func (g *gap0795) handOver() {
	g.t.Helper()
	for _, args := range [][]string{{"chown", "-R", fmt.Sprintf("%d:%d", gap0795UID, gap0795UID), filepath.Join(g.base, "work")}, {"chmod", "-R", "a+rX", g.origin}} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			g.t.Fatalf("%v: %v %s", args, err, out)
		}
	}
}

// run is the relay's exec: a GitCommand request goes to the separated
// relay's git operation; everything else runs as the agent's user (a
// relay of either kind runs exec commands as the agent).
func (g *gap0795) run(ctx context.Context, argv []string, dir string, env map[string]string, _ time.Duration) (string, string, int, error) {
	if len(argv) > 0 && argv[0] == relay.GitCommand {
		out, errs, code := relay.GitOpForTest(ctx, argv, dir, env, gap0795UID, gap0795UID, []string{g.parent}, g.wrap)
		return out, errs, code, nil
	}
	if len(argv) >= 3 && argv[0] == "sh" && argv[1] == "-c" && strings.HasPrefix(argv[2], relay.GitPrelude) {
		argv = append([]string(nil), argv...)
		argv[2] = g.wrap + argv[2]
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: gap0795UID, Gid: gap0795UID, Groups: []uint32{gap0795UID}}}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.String(), errb.String(), ee.ExitCode(), nil
	}
	if errors.Is(err, exec.ErrNotFound) {
		return "", err.Error(), relay.ExitNotRunnable, nil
	}
	return out.String(), errb.String(), 0, err
}

// GAP-0795: the review read the agent's loose objects as they were, and
// git does not check a loose object's content against its id on read. An
// agent that writes other content under the id of a blob it committed
// (here before the review; a racing process can do it between the pack and
// the review) made the review show that content: a file with a credential
// placeholder read as a plain one, and nothing refused. The separated relay
// keeps only objects index-pack computed from their content, so the review
// refuses the checkout instead of describing it wrongly.
func TestGAP0795ReviewRefusesObjectsNotMatchingTheirIDs(t *testing.T) {
	g := newGAP0795(t)
	g.write("npmrc", "//r/:_authToken="+kit.PlaceholderSecret+"\n")
	g.git(g.repo, "add", ".")
	g.git(g.repo, "commit", "-qm", "work")
	id := g.git(g.repo, "rev-parse", "HEAD:npmrc")
	// Other content under the blob's id: a plain file.
	decoy := "registry=https://r.example.test/\n"
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	fmt.Fprintf(zw, "blob %d\x00%s", len(decoy), decoy)
	zw.Close()
	obj := filepath.Join(g.repo, ".git", "objects", id[:2], id[2:])
	if err := os.Remove(obj); err != nil {
		t.Fatalf("the blob is not loose: %v", err)
	}
	if err := os.WriteFile(obj, z.Bytes(), 0o444); err != nil {
		t.Fatal(err)
	}
	g.handOver()

	p, err := workspace.PrepareBranchPush(context.Background(), g.run, filepath.Join(g.base, "work"), "a1", gap0795Origin, nil)
	if err == nil {
		defer p.Discard(context.Background(), g.run)
		t.Fatalf("the review read content that is not its id and refused nothing: placeholder files %v (the commit adds npmrc with one)", p.Placeholder)
	}
	var pe *workspace.BranchPushError
	if !errors.As(err, &pe) || pe.Kind != "objects" && pe.Kind != "failed" {
		t.Fatalf("refusal %v, want the checkout's objects refused", err)
	}
	t.Logf("refused (%s): %v", pe.Kind, err)
	if left, _ := filepath.Glob(filepath.Join(g.parent, "defenseclaw-relay-git", "gp-*")); len(left) != 0 {
		t.Errorf("a refused review left its copy: %v", left)
	}
}

// GAP-0795 (and the in-actor config race of GAP-1073): the review's
// scratch folders, the copy it reads and the push repository were the
// agent's, so a racing agent process could rewrite them. On a separated
// relay the copy is the relay's (root, 0700, in a root-owned parent), the
// agent's user cannot write in it, the review reads it with no warning,
// the push sends exactly the reviewed commit from it, and the discard
// removes it.
func TestGAP0795ReviewCopyIsTheRelays(t *testing.T) {
	g := newGAP0795(t)
	g.write("app.txt", "work\n")
	g.git(g.repo, "add", ".")
	g.git(g.repo, "commit", "-qm", "work")
	head := g.git(g.repo, "rev-parse", "HEAD")
	g.handOver()
	ctx := context.Background()

	p, err := workspace.PrepareBranchPush(ctx, g.run, filepath.Join(g.base, "work"), "a1", gap0795Origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard(ctx, g.run)
	if p.Commits != 1 || len(p.Files) != 1 || p.Files[0] != "app.txt" || p.Commit != head {
		t.Fatalf("review: %d commits, files %v, commit %s (want %s)", p.Commits, p.Files, p.Commit, head)
	}
	copies, _ := filepath.Glob(filepath.Join(g.parent, "defenseclaw-relay-git", "gp-*"))
	if len(copies) != 1 {
		t.Fatalf("the review's copy is not the relay's: relay copies %v", copies)
	}
	fi, err := os.Lstat(copies[0])
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || fi.Mode().Perm() != 0o700 {
		t.Fatalf("copy %s: uid %d mode %v, want the relay's 0700", copies[0], st.Uid, fi.Mode().Perm())
	}
	if _, _, code, _ := g.run(ctx, []string{"sh", "-c", `: > "$1/g/x" || : > "$1/x"`, "sh", copies[0]}, "/", nil, time.Minute); code == 0 {
		t.Fatal("the agent's user wrote in the relay's copy")
	}
	if err := p.Push(ctx, g.run, "agent/fix", "a1", ""); err != nil {
		t.Fatal(err)
	}
	if got := g.git(g.base, "--git-dir", g.origin, "rev-parse", "refs/heads/agent/fix"); got != head {
		t.Fatalf("origin agent/fix %s, want %s", got, head)
	}
	p.Discard(ctx, g.run)
	if left, _ := filepath.Glob(filepath.Join(g.parent, "defenseclaw-relay-git", "gp-*")); len(left) != 0 {
		t.Errorf("discard left the copy: %v", left)
	}
}
