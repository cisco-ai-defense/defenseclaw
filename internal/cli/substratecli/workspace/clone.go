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
	"strings"
	"time"
	"unicode"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
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
type CloneError struct {
	URL, Message string
	Exit         int
}

func (e *CloneError) Error() string {
	msg := fmt.Sprintf("git could not clone %s in the agent: %s", e.URL, e.Message)
	low := strings.ToLower(e.Message)
	switch {
	case strings.Contains(low, "could not read username") || strings.Contains(low, "authentication failed") ||
		strings.Contains(low, "terminal prompts disabled") || strings.Contains(low, "403") || strings.Contains(low, "401"):
		msg += ". The repository needs a credential the cluster does not add for this host; ask your administrator to allow it for your profile"
	case strings.Contains(low, "permission denied (publickey)") || strings.Contains(low, "host key verification"):
		msg += ". The agent has no SSH key; use the https:// address, for which the cluster adds the credential"
	case strings.Contains(low, "could not resolve host") || strings.Contains(low, "connection refused") || strings.Contains(low, "403 forbidden"):
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
func Clone(ctx context.Context, c *Client, dataDir, name, rawURL, ref string) (*CloneResult, error) {
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
	// swaps for the bound token. No prompt, no local or ext transport.
	if err := run("git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
		"clone", "--quiet", "--", rawURL, dir); err != nil {
		return nil, err
	}
	if ref != "" {
		if err := run("git", "-C", dir, "-c", "advice.detachedHead=false", "checkout", "--quiet", ref, "--"); err != nil {
			return nil, err
		}
	}
	rec := &hostRecord{Version: hostRecordVersion, Name: name, Folder: path.Base(dir), RemoteDir: dir,
		CloneURL: rawURL, CloneRef: ref, UploadedAt: time.Now().UTC()}
	res := &CloneResult{Dir: dir}
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
