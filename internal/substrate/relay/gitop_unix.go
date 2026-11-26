// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// gitScratchParents are the folders, in order, where a separated relay
// keeps its review repositories (gitScratchRoot). A test sets them.
var gitScratchParents = []string{"/var/tmp", "/tmp", "/run"}

const (
	// gitScratchName is the relay's folder in a scratch parent.
	gitScratchName = "defenseclaw-relay-git"
	// maxGitSnapshot bounds the pack the agent's user streams to the relay.
	maxGitSnapshot int64 = 8 << 30
	// gitSnapshotLife is how long a review repository the launcher never
	// pushed or discarded stays (a launcher that died).
	gitSnapshotLife = 24 * time.Hour
)

var (
	gitTokenRE  = regexp.MustCompile(`^gp-[0-9]+$`)
	gitCommitRE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// gitTestWrap, set only by tests, is shell put before every script the
// relay runs as its own user (a git function that maps the test origin).
var gitTestWrap string

// runGitOp runs a GitCommand exec request (GAP-0795). A relay of the
// agent's own user answers ExitGitUnseparated, and the launcher runs the
// in-actor scripts. A separated relay runs the operation with its fixed
// scripts: only the pack of the commit is made as the agent's user, in
// dir; everything else runs as the relay's user in a folder only the
// relay can write, with the relay's environment (never the request's, so
// nothing the launcher or the agent sets reaches a root process). The
// exit code is the script's (6 to 14), 2 for a bad request.
func runGitOp(ctx context.Context, argv []string, dir string, env map[string]string, sp *separation, stdout, stderr io.Writer) int {
	if sp == nil || sp.cred == nil {
		fmt.Fprintln(stderr, "the relay runs as the agent's user")
		return ExitGitUnseparated
	}
	bad := func(what string) int {
		fmt.Fprintf(stderr, "%s: %s\n", GitCommand, what)
		return 2
	}
	if len(argv) < 2 {
		return bad("no operation")
	}
	root, err := gitScratchRoot()
	if err != nil && argv[1] != "discard" {
		fmt.Fprintln(stderr, err.Error())
		return 6
	}
	switch op, args := argv[1], argv[2:]; {
	case op == "review" && len(args) == 5:
		objs, url, c := args[0], args[1], args[2]
		if !filepath.IsAbs(objs) || !strings.HasPrefix(url, "https://") || !gitCommitRE.MatchString(c) {
			return bad("review OBJECTS URL COMMIT PLACEHOLDER REPLACED")
		}
		return gitReview(ctx, root, objs, url, c, args[3], args[4], dir, env, sp, stdout, stderr)
	case op == "push" && len(args) == 8:
		snap, ok := gitSnapshot(root, args[0])
		if !ok || !strings.HasPrefix(args[1], "https://") || !gitCommitRE.MatchString(args[2]) {
			return bad("push SNAPSHOT URL COMMIT BRANCH LABEL PREV SEEN PACK")
		}
		return gitRelayRun(ctx, snap, GitPushScript, nil, stdout, stderr, append([]string{snap}, args[1:]...)...)
	case op == "discard" && len(args) == 1:
		if snap, ok := gitSnapshot(root, args[0]); ok {
			_ = os.RemoveAll(snap)
		}
		return 0
	}
	return bad("unknown operation or arguments")
}

// gitReview makes the relay's review repository: origin's refs as the
// relay's user, the pack of the commit made by the agent's user and
// checked object by object into the relay's repository, then the review of
// that repository only. On success the folder stays for the push (its
// name is the "snapshot" frame); else it goes.
func gitReview(ctx context.Context, root, objs, url, c, ph, rp, dir string, env map[string]string, sp *separation, stdout, stderr io.Writer) int {
	sweepGitSnapshots(root)
	R, err := os.MkdirTemp(root, "gp-")
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 6
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(R)
		}
	}()
	if code := gitRelayRun(ctx, R, gitRelayInitScript, nil, io.Discard, stderr, R, url); code != 0 {
		return code
	}
	refs, err := os.ReadFile(filepath.Join(R, "refs"))
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 6
	}
	if code := gitSnapshotPack(ctx, R, objs, c, refs, dir, env, sp, stderr); code != 0 {
		return code
	}
	if code := gitRelayRun(ctx, R, gitRelayReviewScript, nil, stdout, stderr, R, url, c, ph, rp, filepath.Base(R)); code != 0 {
		return code
	}
	ok = true
	return 0
}

// gitSnapshotPack streams the pack the agent's user makes of c (and of
// origin's refs the checkout holds) into index-pack, run as the relay's
// user in R/g. The agent's exit codes 12 (alternates) and 13 (missing
// objects) pass through; a pack index-pack refuses is ExitGitObjects.
func gitSnapshotPack(ctx context.Context, R, objs, c string, refs []byte, dir string, env map[string]string, sp *separation, stderr io.Writer) int {
	ids := map[string]bool{}
	for _, l := range strings.Split(string(refs), "\n") {
		if id, _, ok := strings.Cut(l, "\t"); ok && gitCommitRE.MatchString(id) {
			ids[id] = true
		}
	}
	in := []string{c}
	for id := range ids {
		in = append(in, id)
	}
	sort.Strings(in[1:])
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	agent := exec.CommandContext(pctx, "sh", "-c", gitPackScript, "sh", objs)
	agent.Dir = dir
	agent.Env = os.Environ()
	for k, v := range env {
		agent.Env = append(agent.Env, k+"="+v)
	}
	agent.Stdin = strings.NewReader(strings.Join(in, "\n") + "\n")
	var aerr bytes.Buffer
	agent.Stderr = &capWriter{w: &aerr, left: 64 << 10}
	setProcessGroup(agent)
	sp.asAgent(agent)
	agent.Cancel = func() error { return killProcessGroup(agent) }
	agent.WaitDelay = 2 * time.Second
	pack, err := agent.StdoutPipe()
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 6
	}
	if err := agent.Start(); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 6
	}
	lr := &io.LimitedReader{R: pack, N: maxGitSnapshot + 1}
	icode := gitRelayRun(pctx, R, gitRelayIndexScript, lr, io.Discard, stderr, R)
	if icode != 0 || lr.N <= 0 {
		cancel()
	}
	_, _ = io.Copy(io.Discard, pack)
	werr := agent.Wait()
	acode := 0
	if werr != nil {
		acode = 6
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			acode = exitCodeOf(ee.ProcessState)
		}
	}
	switch {
	case lr.N <= 0:
		fmt.Fprintf(stderr, "the agent's commits are larger than %d bytes\n", maxGitSnapshot)
		return 6
	case acode == 12 || acode == 13:
		_, _ = stderr.Write(aerr.Bytes())
		return acode
	case icode != 0:
		return icode
	case acode != 0:
		_, _ = stderr.Write(aerr.Bytes())
		return 6
	}
	return 0
}

// gitRelayRun runs script as the relay's own user in dir with the relay's
// environment, TMPDIR in dir, git's prompts off.
func gitRelayRun(ctx context.Context, dir, script string, stdin io.Reader, stdout, stderr io.Writer, args ...string) int {
	cmd := exec.CommandContext(ctx, "sh", append([]string{"-c", gitTestWrap + script, "sh"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TMPDIR="+dir, "GIT_TERMINAL_PROMPT=0")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := exitCodeOf(ee.ProcessState); code != ExitNotRunnable && code != ExitGitUnseparated {
			return code
		}
	}
	// Never an answer the launcher reads as an older or unseparated relay.
	fmt.Fprintln(stderr, err.Error())
	return 6
}

// gitScratchRoot is the relay's folder for review repositories: its own
// 0700 folder in the first scratch parent whose every folder up to / is
// root's and writable by no one else (or sticky), so the agent's user can
// neither write in it nor move it.
func gitScratchRoot() (string, error) {
	for _, p := range gitScratchParents {
		if !rootOwnedChain(p) {
			continue
		}
		d := filepath.Join(p, gitScratchName)
		_ = os.Mkdir(d, 0o700)
		if ownDir(d) {
			return d, nil
		}
	}
	return "", errors.New("the relay has no folder only it can write (" + strings.Join(gitScratchParents, ", ") + ")")
}

// rootOwnedChain reports p and every folder above it as root's, not a
// link, and writable by group or others only with the sticky bit.
func rootOwnedChain(p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	for p = filepath.Clean(p); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return false
		}
		if p == filepath.Dir(p) {
			return true
		}
	}
}

// ownDir reports d as a folder (not a link) of the relay's user, 0700.
func ownDir(d string) bool {
	fi, err := os.Lstat(d)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// gitSnapshot is the review repository tok names in root, when it is one
// the relay made (a review that succeeded).
func gitSnapshot(root, tok string) (string, bool) {
	if root == "" || !gitTokenRE.MatchString(tok) {
		return "", false
	}
	d := filepath.Join(root, tok)
	return d, ownDir(d)
}

// sweepGitSnapshots removes review repositories older than
// gitSnapshotLife (their launcher never pushed or discarded them).
func sweepGitSnapshots(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && gitTokenRE.MatchString(e.Name()) && time.Since(fi.ModTime()) > gitSnapshotLife {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

// capWriter keeps the first left bytes written to it.
type capWriter struct {
	w    io.Writer
	left int
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.left > 0 {
		n := min(len(p), c.left)
		_, _ = c.w.Write(p[:n])
		c.left -= n
	}
	return len(p), nil
}
