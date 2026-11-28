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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
// agent's own user answers ExitGitUnseparated, and one whose image has no
// programs only root can change ExitGitNoRootGit; the launcher then runs
// the in-actor scripts. A separated relay runs the operation with its fixed
// scripts: only the pack of the commit is made as the agent's user, in
// dir; everything else runs as the relay's user in a folder only the
// relay can write, with an environment of its own (gitRelayEnv: never the
// request's or the image's, so nothing the launcher or the agent sets or
// writes reaches a root process). The exit code is the script's (6 to 14),
// 2 for a bad request.
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
	if argv[1] == "discard" && len(argv) == 3 {
		root, _ := gitScratchRoot()
		if snap, ok := gitSnapshot(root, argv[2]); ok {
			_ = os.RemoveAll(snap)
		}
		return 0
	}
	root, err := gitScratchRoot()
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 6
	}
	renv, err := gitRelayEnv(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		if errors.Is(err, errNoRootGit) {
			return ExitGitNoRootGit
		}
		return 6
	}
	switch op, args := argv[1], argv[2:]; {
	case op == "review" && len(args) == 5:
		objs, url, c := args[0], args[1], args[2]
		if !filepath.IsAbs(objs) || !strings.HasPrefix(url, "https://") || !gitCommitRE.MatchString(c) {
			return bad("review OBJECTS URL COMMIT PLACEHOLDER REPLACED")
		}
		return gitReview(ctx, renv, root, objs, url, c, args[3], args[4], dir, env, sp, stdout, stderr)
	case op == "push" && len(args) == 8:
		snap, ok := gitSnapshot(root, args[0])
		if !ok || !strings.HasPrefix(args[1], "https://") || !gitCommitRE.MatchString(args[2]) {
			return bad("push SNAPSHOT URL COMMIT BRANCH LABEL PREV SEEN PACK")
		}
		return gitRelayRun(ctx, renv, snap, GitPushScript, nil, stdout, stderr, append([]string{snap}, args[1:]...)...)
	}
	return bad("unknown operation or arguments")
}

// gitReview makes the relay's review repository: origin's refs as the
// relay's user, the pack of the commit made by the agent's user and
// checked object by object into the relay's repository, then the review of
// that repository only. On success the folder stays for the push (its
// name is the "snapshot" frame); else it goes.
func gitReview(ctx context.Context, renv []string, root, objs, url, c, ph, rp, dir string, env map[string]string, sp *separation, stdout, stderr io.Writer) int {
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
	if code := gitRelayRun(ctx, renv, R, gitRelayInitScript, nil, io.Discard, stderr, R, url); code != 0 {
		return code
	}
	refs, err := os.ReadFile(filepath.Join(R, "refs"))
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 6
	}
	if code := gitSnapshotPack(ctx, renv, R, objs, c, refs, dir, env, sp, stderr); code != 0 {
		return code
	}
	if code := gitRelayRun(ctx, renv, R, gitRelayReviewScript, nil, stdout, stderr, R, url, c, ph, rp, filepath.Base(R)); code != 0 {
		return code
	}
	ok = true
	return 0
}

// gitSnapshotPack streams the pack the agent's user makes of c (and of
// origin's refs the checkout holds) into index-pack, run as the relay's
// user in R/g. The agent's exit codes 12 (alternates) and 13 (missing
// objects) pass through; a pack index-pack refuses is ExitGitObjects.
func gitSnapshotPack(ctx context.Context, renv []string, R, objs, c string, refs []byte, dir string, env map[string]string, sp *separation, stderr io.Writer) int {
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
	icode := gitRelayRun(pctx, renv, R, gitRelayIndexScript, lr, io.Discard, stderr, R)
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

// gitRelayRun runs script as the relay's own user in dir: /bin/sh by its
// path, the environment renv of gitRelayEnv, HOME and TMPDIR in dir.
func gitRelayRun(ctx context.Context, renv []string, dir, script string, stdin io.Reader, stdout, stderr io.Writer, args ...string) int {
	cmd := exec.CommandContext(ctx, gitRelayShell, append([]string{"-c", gitTestWrap + script, "sh"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(slices.Clip(renv), "HOME="+dir, "TMPDIR="+dir)
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
		if code := exitCodeOf(ee.ProcessState); code != ExitNotRunnable && code != ExitGitUnseparated && code != ExitGitNoRootGit {
			return code
		}
	}
	// Never an answer the launcher reads as an older or unseparated relay.
	fmt.Fprintln(stderr, err.Error())
	return 6
}

// errNoRootGit is an image without the programs, only root can change,
// that the relay's own runs need (an image property the agent cannot make).
var errNoRootGit = errors.New("the relay will not run git as root")

// gitRelayShell runs the relay's own scripts. It is named by its path:
// the image PATH may name a folder the agent can write (GAP-0795 H1).
const gitRelayShell = "/bin/sh"

// gitSystemPath are the only folders the relay's own runs look programs up
// in (gitRelayEnv). The image PATH is never read for them: it may name a
// folder the agent can write, or replace with a link at run time, and so
// pick the programs root runs or make the relay give up its own review
// (GAP-0795 H3). A test sets them.
var gitSystemPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// gitRelayPrograms are the programs the relay's own scripts (gitpush.go)
// and the kit's credential helper run by name.
var gitRelayPrograms = []string{"git", "awk", "cat", "cp", "cut", "env", "mkdir", "mktemp", "rm", "sed", "sort", "tr", "wc"}

// gitRelayEnv is the whole environment of the relay's own runs, as root
// (GAP-0795 H1, H2, H3): an allow-list, never the relay's environment with
// names taken out. PATH is the folders of gitSystemPath that root alone can
// write, reached through links only root can change (rootOnlyDir), by
// their resolved path; nothing of the image PATH. /bin/sh, every program
// of gitRelayPrograms and every file of git's own exec-path folder must be
// root's files there, else the operation is refused (errNoRootGit): that
// depends only on files root controls, never on anything the agent can
// write. The agent's HOME and any XDG_* or GIT_* name stay out (git reads
// attributes and config from them); gitRelayRun sets HOME and TMPDIR to the
// relay's 0700 folder. Locale C keeps the scripts' sort and awk byte-wise.
func gitRelayEnv(ctx context.Context) ([]string, error) {
	var dirs []string
	seen := map[string]bool{}
	for _, d := range gitSystemPath {
		if r, ok := rootOnlyDir(d); ok && !seen[r] {
			seen[r] = true
			dirs = append(dirs, r)
		}
	}
	if !rootOnlyFile(gitRelayShell) {
		return nil, fmt.Errorf("%w: %s is not a program only root can change", errNoRootGit, gitRelayShell)
	}
	var git string
	for _, n := range gitRelayPrograms {
		p, err := rootOnlyProgram(dirs, n)
		if err != nil {
			return nil, err
		}
		if n == "git" {
			git = p
		}
	}
	env := []string{"PATH=" + strings.Join(dirs, ":"), "LC_ALL=C", "GIT_TERMINAL_PROMPT=0"}
	cmd := exec.CommandContext(ctx, git, "--exec-path")
	cmd.Env, cmd.Dir = append(slices.Clip(env), "HOME=/"), "/"
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("the relay will not run git as root: %s --exec-path: %v", git, err)
	}
	xp := strings.TrimSpace(string(out))
	if bad := rootOnlyTree(xp); bad != "" {
		return nil, fmt.Errorf("%w: its program folder %q holds %s, not a file only root can change", errNoRootGit, xp, bad)
	}
	return env, nil
}

// maxLinkHops bounds the links rootResolve follows, as the kernel does.
const maxLinkHops = 40

// rootResolve is p with every link resolved hop by hop, when no hop is one
// another user can change (GAP-0795 H3, N1): every folder on the way is
// root's and writable by no one else (or sticky, as in rootOwnedChain), and
// a link is followed only when the folder that holds it is root's and
// writable by root alone. Else false: the path is refused, never followed.
// (filepath.EvalSymlinks follows a link the agent owns, or one in a folder
// it can write, to any folder it names, and such a hop can change after
// the check.)
func rootResolve(p string) (string, bool) {
	if !filepath.IsAbs(p) || !rootDirAt("/", true) {
		return "", false
	}
	cur, rest, hops := "/", strings.Split(filepath.Clean(p), "/"), 0
	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, name)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", false
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			t, err := os.Readlink(next)
			if hops++; err != nil || t == "" || hops > maxLinkHops || !rootDirAt(cur, false) {
				return "", false
			}
			if filepath.IsAbs(t) {
				cur = "/"
			}
			rest = append(strings.Split(t, "/"), rest...)
			continue
		}
		if fi.IsDir() {
			if !rootOwnedInfo(fi, true) {
				return "", false
			}
		} else if len(rest) > 0 {
			return "", false
		}
		cur = next
	}
	return cur, true
}

// rootDirAt reports d (not a link) as a folder of root's that no one else
// can write (or sticky, when sticky is true).
func rootDirAt(d string, sticky bool) bool {
	fi, err := os.Lstat(d)
	return err == nil && fi.IsDir() && rootOwnedInfo(fi, sticky)
}

// rootOwnedInfo reports fi as root's and writable by no one else (or a
// sticky folder, when sticky is true).
func rootOwnedInfo(fi fs.FileInfo, sticky bool) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && (fi.Mode().Perm()&0o022 == 0 || sticky && fi.Mode()&fs.ModeSticky != 0)
}

// rootOnlyDir is d resolved hop by hop (rootResolve) when that folder is
// writable by root alone (a sticky folder such as /tmp lets anyone add a
// program).
func rootOnlyDir(d string) (string, bool) {
	r, ok := rootResolve(d)
	if !ok || !isRootOnlyDir(r) {
		return "", false
	}
	return r, true
}

// isRootOnlyDir reports r (links resolved) as a folder only root can write,
// in a chain of root's folders.
func isRootOnlyDir(r string) bool {
	if !rootOwnedChain(r) {
		return false
	}
	fi, err := os.Lstat(r)
	return err == nil && fi.Mode().Perm()&0o022 == 0
}

// rootOnlyFile reports p, resolved hop by hop (rootResolve), as a regular
// file of root's, writable by root alone, in a folder only root can write.
func rootOnlyFile(p string) bool {
	r, ok := rootResolve(p)
	if !ok {
		return false
	}
	fi, err := os.Lstat(r)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && isRootOnlyDir(filepath.Dir(r))
}

// maxExecPathEntries bounds the entries rootOnlyTree checks.
const maxExecPathEntries = 1 << 14

// rootOnlyTree checks git's exec-path folder file by file (GAP-0795 N2):
// git runs its helpers (git-remote-https) from it as root, so the folder
// and every folder and file in it must be root's and writable by root
// alone, and a link in it must lead, hop by hop (rootResolve), to such a
// file or folder. It names the first entry that is not ("" when every one
// is).
func rootOnlyTree(xp string) string {
	r, ok := rootResolve(xp)
	if !ok || !isRootOnlyDir(r) {
		return "the folder itself"
	}
	bad, n := "", 0
	_ = filepath.WalkDir(r, func(p string, e fs.DirEntry, err error) error {
		if n++; err != nil || n > maxExecPathEntries {
			bad = p
			return fs.SkipAll
		}
		t := p
		if e.Type()&fs.ModeSymlink != 0 {
			if t, ok = rootResolve(p); !ok {
				bad = p
				return fs.SkipAll
			}
		}
		fi, err := os.Lstat(t)
		if err != nil || !fi.Mode().IsRegular() && !fi.IsDir() || !rootOwnedInfo(fi, false) {
			bad = p
			return fs.SkipAll
		}
		return nil
	})
	return bad
}

// rootOnlyProgram is the file the shell runs for name, the first one in
// dirs: it must be a program only root can change.
func rootOnlyProgram(dirs []string, name string) (string, error) {
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm()&0o111 == 0 || !rootOnlyFile(p) {
			return "", fmt.Errorf("%w: %s is not a program only root can change", errNoRootGit, p)
		}
		return p, nil
	}
	return "", fmt.Errorf("%w: no %s in a folder only root can write (%s)", errNoRootGit, name, strings.Join(dirs, ":"))
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
