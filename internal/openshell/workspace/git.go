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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gitsafe"
)

// gitIdentity is the author/committer of every commit this package writes.
// gitsafe hides the operator's global config, so it has to be explicit.
var gitIdentity = []string{
	"user.name=DefenseClaw",
	"user.email=defenseclaw@localhost",
}

// gitHardening is layered on top of gitsafe's flags for every call. It
// closes the remaining paths by which repository content could make git
// start another program or reach the network: signing programs, credential
// helpers, auto-maintenance and every transport except local files.
var gitHardening = []string{
	"core.quotePath=false",
	"commit.gpgSign=false",
	"tag.gpgSign=false",
	"credential.helper=",
	"core.sshCommand=false",
	"core.askPass=false",
	"gc.auto=0",
	"maintenance.auto=false",
	"fetch.recurseSubmodules=false",
	"submodule.recurse=false",
	"protocol.allow=never",
	"protocol.file.allow=always",
	"advice.addEmbeddedRepo=false",
	"advice.detachedHead=false",
	"init.defaultBranch=main",
}

// gitCmd describes one hardened git invocation. dir is the process working
// directory; gitDir/workTree, when set, are passed explicitly so git never
// discovers a repository on its own.
type gitCmd struct {
	dir      string
	gitDir   string
	workTree string
	index    string
	config   []string
	stdin    io.Reader
}

// GitError carries a failed git invocation's exit status and stderr.
type GitError struct {
	Args     []string
	ExitCode int
	Stderr   string
	Err      error
}

func (e *GitError) Error() string {
	stderr := strings.TrimSpace(e.Stderr)
	if len(stderr) > 2048 {
		stderr = stderr[:2048] + "…"
	}
	sub := ""
	if len(e.Args) > 0 {
		sub = e.Args[0]
	}
	if stderr == "" {
		return fmt.Sprintf("workspace: git %s: %v", sub, e.Err)
	}
	return fmt.Sprintf("workspace: git %s: %s", sub, stderr)
}

func (e *GitError) Unwrap() error { return e.Err }

// command builds the hardened git command; cleanup removes its private
// HOME (gitsafe.Command) and runs once the command has finished.
func (c gitCmd) command(ctx context.Context, args []string) (cmd *exec.Cmd, cleanup func(), err error) {
	full := make([]string, 0, len(args)+2*len(gitHardening)+8)
	for _, kv := range gitHardening {
		full = append(full, "-c", kv)
	}
	for _, kv := range gitIdentity {
		full = append(full, "-c", kv)
	}
	for _, kv := range c.config {
		full = append(full, "-c", kv)
	}
	if c.gitDir != "" {
		full = append(full, "--git-dir="+c.gitDir)
	}
	if c.workTree != "" {
		full = append(full, "--work-tree="+c.workTree)
	}
	full = append(full, args...)
	dir := c.dir
	if dir == "" {
		dir = c.gitDir
	}
	cmd, cleanup, err = gitsafe.Command(ctx, dir, full...)
	if err != nil {
		return nil, nil, err
	}
	if c.index != "" {
		// gitsafe strips every inherited GIT_* variable; this is the one
		// this package sets on purpose.
		cmd.Env = append(cmd.Env, "GIT_INDEX_FILE="+c.index)
	}
	if c.stdin != nil {
		cmd.Stdin = c.stdin
	}
	return cmd, cleanup, nil
}

// output runs git and returns stdout. A non-zero exit is a *GitError.
func (c gitCmd) output(ctx context.Context, args ...string) ([]byte, error) {
	return c.strict(ctx, args...)
}

// outputCode runs git and returns stdout plus the exit code. Exit 1 is
// returned as an answer, not an error, for the plumbing commands that use it
// that way (merge-base --is-ancestor, diff --quiet, merge-tree, rev-parse
// -q --verify); any other failure is a *GitError carrying stderr.
func (c gitCmd) outputCode(ctx context.Context, args ...string) ([]byte, int, error) {
	cmd, cleanup, err := c.command(ctx, args)
	if err != nil {
		return nil, -1, err
	}
	defer cleanup()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if runErr == nil {
		return stdout.Bytes(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) && ctx.Err() == nil {
		code := exitErr.ExitCode()
		if code == 1 {
			return stdout.Bytes(), code, nil
		}
		return stdout.Bytes(), code, &GitError{Args: args, ExitCode: code, Stderr: stderr.String(), Err: runErr}
	}
	if ctx.Err() != nil {
		return nil, -1, &GitError{Args: args, ExitCode: -1, Stderr: stderr.String(), Err: ctx.Err()}
	}
	return nil, -1, &GitError{Args: args, ExitCode: -1, Stderr: stderr.String(), Err: runErr}
}

// run runs git and fails on any non-zero exit, including 1.
func (c gitCmd) run(ctx context.Context, args ...string) error {
	_, err := c.strict(ctx, args...)
	return err
}

// strict runs git and treats every non-zero exit as a *GitError with stderr.
func (c gitCmd) strict(ctx context.Context, args ...string) ([]byte, error) {
	cmd, cleanup, err := c.command(ctx, args)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		code := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return stdout.Bytes(), &GitError{Args: args, ExitCode: code, Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

// line runs git strictly and returns the first line of stdout, trimmed.
func (c gitCmd) line(ctx context.Context, args ...string) (string, error) {
	out, err := c.strict(ctx, args...)
	if err != nil {
		return "", err
	}
	s := string(out)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s), nil
}

// splitNUL splits -z output, dropping the empty trailing element.
func splitNUL(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	parts := strings.Split(string(b), "\x00")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

var oidRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func isOID(s string) bool { return oidRE.MatchString(s) }

// gitVersion is the host git version, parsed once.
type gitVersion struct{ major, minor, patch int }

func (v gitVersion) atLeast(major, minor int) bool {
	return v.major > major || (v.major == major && v.minor >= minor)
}

func (v gitVersion) String() string { return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch) }

var gitVersionRE = regexp.MustCompile(`git version (\d+)\.(\d+)(?:\.(\d+))?`)

// gitVersionCache remembers the host git version once a probe succeeds. A
// failed probe is not remembered: it may only mean that the caller's
// context ended, or that git was installed since.
type gitVersionCache struct {
	mu sync.Mutex
	v  gitVersion
	ok bool
}

var hostGit gitVersionCache

// get returns the cached version or runs probe (git version) for it.
func (c *gitVersionCache) get(ctx context.Context, probe func(context.Context) ([]byte, error)) (gitVersion, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok {
		return c.v, nil
	}
	out, err := probe(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return gitVersion{}, fmt.Errorf("workspace: check the git version: %w", ctxErr)
		}
		return gitVersion{}, fmt.Errorf("workspace: git is required on this machine: %w", err)
	}
	m := gitVersionRE.FindStringSubmatch(string(out))
	if m == nil {
		return gitVersion{}, fmt.Errorf("workspace: unrecognized git version %q", strings.TrimSpace(string(out)))
	}
	var v gitVersion
	v.major, _ = strconv.Atoi(m[1])
	v.minor, _ = strconv.Atoi(m[2])
	if m[3] != "" {
		v.patch, _ = strconv.Atoi(m[3])
	}
	c.v, c.ok = v, true
	return v, nil
}

// hostGitVersion reports the host git version. It runs outside any
// repository; dir is accepted for call-site symmetry only.
func hostGitVersion(ctx context.Context, _ string) (gitVersion, error) {
	return hostGit.get(ctx, func(ctx context.Context) ([]byte, error) {
		return gitCmd{dir: os.TempDir()}.strict(ctx, "version")
	})
}

// minGitMajor/minGitMinor is the oldest git this package drives: 2.29 adds
// fetch --no-write-fetch-head and --no-auto-maintenance, used for every
// fetch into a repository DefenseClaw does not own.
const (
	minGitMajor = 2
	minGitMinor = 29
)

func requireGit(ctx context.Context, dir string) (gitVersion, error) {
	v, err := hostGitVersion(ctx, dir)
	if err != nil {
		return v, err
	}
	if !v.atLeast(minGitMajor, minGitMinor) {
		return v, fmt.Errorf("workspace: git %s is too old; DefenseClaw needs git %d.%d or newer", v, minGitMajor, minGitMinor)
	}
	return v, nil
}
