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
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/config"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/reasons"
)

// run --clone (GAP-0175): the repository is cloned inside the actor through
// the relay, so it goes out through the actor's egress rules. A private
// repository works the way every git call in the actor does: the image's
// root-owned credential helper (kit gitConfig) answers with a placeholder,
// and egress swaps it for the person's or the shared token on the hosts the
// token is bound to. Nothing of this computer's git credentials is used.

const cloneTimeout = 15 * time.Minute

// CloneResult is where a clone landed in the actor. Note, when set, says
// why pull will not be able to review the agent's work on it.
type CloneResult struct {
	Dir  string
	Note string
	// Warnings say what the clone could not bring (LFS files left as
	// pointers); the clone itself worked.
	Warnings []string
}

// CloneOptions are the cluster's substrate.git switches for one clone.
type CloneOptions struct {
	// Submodules clones submodules too (substrate.git.submodules).
	Submodules bool
	// LFS fetches LFS files (substrate.git.lfs); off leaves pointers.
	LFS bool
}

var (
	scpLikeRE = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^/][^\x00]*$`)
	refRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)
)

// CheckCloneURL refuses an address git would treat as something other than
// a repository on a server: options, local paths, file and ext transports,
// and credentials written into it (the cluster adds those).
func CheckCloneURL(raw string) error {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "" || strings.HasPrefix(raw, "-") || strings.ContainsAny(raw, "\x00\r\n \t"):
		return errors.New("--clone needs a repository address such as https://git.example.test/team/app.git")
	case scpLikeRE.MatchString(raw):
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("--clone needs a repository address such as https://git.example.test/team/app.git")
	}
	switch u.Scheme {
	case "https", "http", "ssh", "git":
	default:
		return fmt.Errorf("--clone takes an https, ssh or git address, not %s", u.Scheme)
	}
	if u.User != nil {
		if _, hasPass := u.User.Password(); hasPass || u.Scheme == "https" || u.Scheme == "http" {
			return errors.New("do not put a user name or token in the --clone address; the cluster adds the credential for hosts it allows")
		}
	}
	return nil
}

// CloneHost is the host git in the actor sends a credential to for raw:
// the https host, or the host of an ssh address the actor's git turns
// into https (rules, substrate.git.https_rewrite, nil for the default;
// and every ssh://git@ address). It is "" for any other address, which
// never asks for a token.
func CloneHost(raw string, rules []config.SubstrateGitRewrite) string {
	raw = strings.TrimSpace(raw)
	if rules == nil {
		rules = config.DefaultSubstrateGitHTTPSRewrite()
	}
	if v, ok := config.RewriteGitURL(raw, rules); ok {
		raw = v
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// CheckCloneRef refuses a --ref git would read as an option.
func CheckCloneRef(ref string) error {
	if ref != "" && !refRE.MatchString(ref) {
		return fmt.Errorf("--ref %q is not a branch, tag or commit name", ref)
	}
	return nil
}

// cloneFolder is the clone's folder name: the repository's.
func cloneFolder(raw string) string {
	p := raw
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		p = u.Path
	} else if _, after, ok := strings.Cut(raw, ":"); ok {
		p = after
	}
	n := strings.TrimSuffix(path.Base(strings.TrimRight(p, "/")), ".git")
	var b strings.Builder
	for _, r := range n {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_', r == '.':
			b.WriteRune(r)
		}
	}
	if s := strings.Trim(b.String(), "."); s != "" {
		return s
	}
	return "repo"
}

// CloneError is a clone git refused in the actor, in its own words.
// Hint, when set, replaces the general advice for a refused credential
// with what this person can do (B1 2.2: the template that covers the host,
// or the add command an administrator approves).
//
// Refused is a host the agent's network rules do not allow, which the
// launcher learned from the gateway's policy explain after the clone
// failed (GAP-0720): a 403 from the egress guard then means the rules,
// not a missing token, so no credential is offered.
type CloneError struct {
	URL, Message string
	Exit         int
	Hint         string
	Refused      string
}

// NeedsCredential reports whether the host refused the clone for want of
// a credential: no user name, a refused placeholder, 401 or 403. It is
// false when the agent's network rules refused a host (Refused).
func (e *CloneError) NeedsCredential() bool {
	if e.Refused != "" {
		return false
	}
	low := strings.ToLower(e.Message)
	return strings.Contains(low, "could not read username") || strings.Contains(low, "authentication failed") ||
		strings.Contains(low, "terminal prompts disabled") || strings.Contains(low, "403") || strings.Contains(low, "401")
}

func (e *CloneError) Error() string {
	msg := fmt.Sprintf("git could not clone %s in the agent: %s", e.URL, e.Message)
	low := strings.ToLower(e.Message)
	switch {
	case e.Refused != "":
		msg += ". The agent's network rules do not allow " + e.Refused + ": " + reasons.Message(reasons.Must("not_in_allow_only"))
	case e.NeedsCredential() && e.Hint != "":
		msg += ". " + e.Hint
	case e.NeedsCredential():
		msg += ". The repository needs a credential the cluster does not add for this host; ask your administrator to allow it for your profile"
	case strings.Contains(low, "permission denied (publickey)") || strings.Contains(low, "host key verification"):
		msg += ". The agent has no SSH key; use the https:// address, for which the cluster adds the credential, or ask your administrator to add this host to substrate.git.https_rewrite"
	case strings.Contains(low, "no space left on device"):
		msg += ". The agent's disk is full; clone a smaller repository, or ask your administrator for a template with more disk"
	case strings.Contains(low, "could not resolve host") || strings.Contains(low, "connection refused"):
		msg += ". The agent's network rules may not allow this host; ask your administrator"
	case strings.Contains(low, "returned error: 503") || strings.Contains(low, "returned error: 502"):
		msg += ". The cluster's network guard refused the request or could not check it; ask your administrator to look at the DefenseClaw egress log for this agent"
	}
	return msg
}

// Clone clones rawURL (at ref) into the actor's working directory. It then
// reads the clone back once, before the agent runs, and keeps it as a host
// copy baseline on this computer (the same private git directory the host
// copy uses), so the agent starts in the clone, checkpoint and undo find it,
// and pull reviews and brings back what the agent changed on any OS.
func Clone(ctx context.Context, c *Client, dataDir, name, rawURL, ref string, opts CloneOptions) (*CloneResult, error) {
	if err := CheckCloneURL(rawURL); err != nil {
		return nil, err
	}
	if err := CheckCloneRef(ref); err != nil {
		return nil, err
	}
	root, err := c.Root(ctx)
	if err != nil {
		return nil, err
	}
	dir := path.Join(root, cloneFolder(rawURL))
	env := map[string]string{"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/true", "SSH_ASKPASS": "/bin/true"}
	if !opts.LFS {
		env["GIT_LFS_SKIP_SMUDGE"] = "1"
	}
	run := func(argv ...string) error {
		res, err := c.Exec(ctx, "", osw.ExecRequest{Argv: argv, Workdir: root, Env: env, Timeout: cloneTimeout})
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return &CloneError{URL: rawURL, Message: lastLine(string(res.Stderr), string(res.Stdout)), Exit: res.ExitCode}
		}
		return nil
	}
	// The image's credential helper stays: its placeholder is what egress
	// swaps for the bound token. No prompt, no local or ext transport; git
	// passes the -c settings on to the submodule clones it starts.
	guard := []string{"git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never"}
	args := append(slices.Clone(guard), "clone", "--quiet")
	if opts.Submodules {
		args = append(args, "--recurse-submodules")
	}
	if err := run(append(args, "--", rawURL, dir)...); err != nil {
		return nil, err
	}
	if ref != "" {
		if err := run("git", "-C", dir, "-c", "advice.detachedHead=false", "checkout", "--quiet", ref, "--"); err != nil {
			return nil, err
		}
		if opts.Submodules {
			if err := run(append(slices.Clone(guard), "-C", dir, "submodule", "update", "--quiet", "--init", "--recursive")...); err != nil {
				return nil, err
			}
		}
	}
	rec := &hostRecord{Version: hostRecordVersion, Name: name, Folder: path.Base(dir), RemoteDir: dir,
		CloneURL: rawURL, CloneRef: ref, UploadedAt: time.Now().UTC()}
	res := &CloneResult{Dir: dir}
	if w := cloneLFSWarning(ctx, c, root, dir, env, opts.LFS); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	if err := cloneBaseline(ctx, c, dataDir, rec); err != nil {
		rec.Baseline, rec.Files, rec.Bytes = "", 0, 0
		res.Note = "pull cannot review this agent's work (" + lastLine(strings.TrimPrefix(err.Error(), "workspace: ")) +
			"); push from inside the agent with git instead"
	}
	if err := rec.save(dataDir); err != nil {
		return nil, fmt.Errorf("workspace: record the clone: %w", err)
	}
	return res, nil
}

// cloneLFSWarning says when files the clone's attributes mark for LFS
// stayed pointers: the template has no git-lfs, or substrate.git.lfs is
// off. It is "" when there are none, or git-lfs fetched them.
func cloneLFSWarning(ctx context.Context, c *Client, root, dir string, env map[string]string, lfsOn bool) string {
	const script = `n=$(git -C "$1" ls-files -- ':(attr:filter=lfs)' | wc -l); if git lfs version >/dev/null 2>&1; then echo "$n lfs"; else echo "$n none"; fi`
	res, err := c.Exec(ctx, "", osw.ExecRequest{Argv: []string{"sh", "-c", script, "sh", dir}, Workdir: root, Env: env, Timeout: time.Minute})
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	var n int
	var tool string
	if _, err := fmt.Sscan(string(res.Stdout), &n, &tool); err != nil || n == 0 {
		return ""
	}
	files := fmt.Sprintf("%d LFS files are pointers", n)
	if n == 1 {
		files = "1 LFS file is a pointer"
	}
	switch {
	case tool != "lfs":
		return "this template has no git-lfs; " + files
	case !lfsOn:
		return "LFS is off on this cluster (substrate.git.lfs); " + files
	}
	return ""
}

// gitRewriteScript writes the https rewrite pairs ($1 from, $2 to, ...)
// into the actor user's git config: a file of its own, included once from
// ~/.config/git/config, so a second start replaces it in place. The pairs
// are argv, never shell text.
const gitRewriteScript = `set -e
d="${XDG_CONFIG_HOME:-$HOME/.config}/git"
f="$d/defenseclaw-rewrite"
mkdir -p "$d"
: > "$f.tmp"
while [ "$#" -ge 2 ]; do git config --file "$f.tmp" --add "url.$2.insteadOf" "$1"; shift 2; done
mv -f "$f.tmp" "$f"
git config --file "$d/config" --get-all include.path 2>/dev/null | grep -qxF defenseclaw-rewrite || git config --file "$d/config" --add include.path defenseclaw-rewrite`

// WriteGitRewrite puts substrate.git.https_rewrite into the actor's git
// config at start (B2 2.5), before any upload or clone, so the agent's own
// git calls turn the same ssh addresses into https. It is a convenience,
// not a control: egress decides what the agent reaches. A pair that fails
// CheckSubstrateGitRewrite is left out.
func WriteGitRewrite(ctx context.Context, c *Client, rules []config.SubstrateGitRewrite) error {
	argv := []string{"sh", "-c", gitRewriteScript, "sh"}
	for _, r := range rules {
		if config.CheckSubstrateGitRewrite(r) == nil {
			argv = append(argv, r.From, r.To)
		}
	}
	root, err := c.Root(ctx)
	if err != nil {
		return err
	}
	res, err := c.Exec(ctx, "", osw.ExecRequest{Argv: argv, Workdir: root, Timeout: time.Minute})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(lastLine(string(res.Stderr), string(res.Stdout)))
	}
	return nil
}

// cloneBaseline reads the fresh clone back (the host copy's own reader:
// regular files only, no .git, no package caches, secret files held back)
// and commits it as the record's baseline in a new private git directory.
func cloneBaseline(ctx context.Context, c *Client, dataDir string, rec *hostRecord) error {
	gitDir := hostGitDir(dataDir, rec.Name)
	_ = os.RemoveAll(gitDir)
	if err := os.MkdirAll(hostDir(dataDir), 0o700); err != nil {
		return err
	}
	if _, err := hostGit(ctx, hostDir(dataDir), nil, nil, "init", "-q", "--bare", gitDir); err != nil {
		return err
	}
	stage := filepath.Join(hostDir(dataDir), rec.Name+".base")
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	files, _, _, err := c.downloadHostTree(ctx, rec, stage)
	if err != nil {
		return err
	}
	base, err := hostCommit(ctx, gitDir, stage, files, "")
	if err != nil {
		return err
	}
	rec.Baseline, rec.Files = base, len(files)
	for _, f := range files {
		rec.Bytes += f.size
	}
	return nil
}

// cloneIgnored drops the files the clone's own ignore rules exclude (build
// output the agent made) unless the baseline has them: a file the clone
// came with is always compared, so an ignore rule cannot hide its change.
func cloneIgnored(ctx context.Context, gitDir, stage, base string, files []hostFile) []hostFile {
	env := []string{"GIT_DIR=" + gitDir}
	out, err := hostGit(ctx, stage, env, nil, "ls-tree", "-r", "-z", "--name-only", base)
	if err != nil {
		return files
	}
	known := map[string]bool{}
	for _, p := range splitNUL(out) {
		known[p] = true
	}
	var in bytes.Buffer
	for _, f := range files {
		if !known[f.rel] {
			in.WriteString(f.rel)
			in.WriteByte(0)
		}
	}
	if in.Len() == 0 {
		return files
	}
	out, _ = hostGit(ctx, stage, append(env, "GIT_WORK_TREE="+stage), in.Bytes(), "check-ignore", "-z", "--stdin", "--no-index")
	ignored := map[string]bool{}
	for _, p := range splitNUL(out) {
		ignored[p] = true
	}
	kept := files[:0]
	for _, f := range files {
		if !ignored[f.rel] {
			kept = append(kept, f)
		}
	}
	return kept
}

func lastLine(v ...string) string {
	for _, s := range v {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		lines := strings.Split(s, "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i]), "fatal:")); l != "" {
				return l
			}
		}
	}
	return "it printed no error"
}
