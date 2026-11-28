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
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Upstream is the server side of a "this checkout" copy (run --clone .).
// The copy ships only the commits after Base (and the working tree, under
// the normal masking rules); the sandbox then fetches the rest of the
// branch's history from URL itself, through its own egress rules, so the
// agent has all of it while nothing but the unpushed work leaves this
// computer. Secret blobs of the shipped commits are withheld as in any copy.
type Upstream struct {
	// Remote is the checkout's remote for the branch (branch.<b>.remote,
	// else origin); URL its credential-free address.
	Remote string `json:"remote"`
	URL    string `json:"url"`
	// Branch is the remote branch Base was measured against (its short
	// name under refs/remotes/<Remote>/).
	Branch string `json:"branch,omitempty"`
	// Base is merge-base(HEAD, the remote-tracking branch); Commits counts
	// base..HEAD and Changes the paths the working tree changes on HEAD.
	Base    string `json:"base"`
	Commits int    `json:"commits"`
	Changes int    `json:"changes"`
	// AtTip: HEAD is the remote-tracking branch's tip. Dirty: the checkout
	// has uncommitted changes (tracked, or untracked and not ignored).
	AtTip bool `json:"-"`
	Dirty bool `json:"-"`
}

// UpstreamError refuses run --clone . and says what to use instead.
type UpstreamError struct{ Msg string }

func (e *UpstreamError) Error() string { return e.Msg }

// ResolveUpstream reads the upstream of the checkout at project without
// changing anything: the remote and its address, the base commit and how
// much local work sits on it. It refuses a folder that is not the top of a
// checkout, a branch with no commit, a remote that is a local path or not
// https (after toHTTPS, which may be nil), and a branch that shares no
// commit with its remote.
func ResolveUpstream(ctx context.Context, project string, toHTTPS func(string) (string, bool)) (*Upstream, error) {
	if !isGitTopLevel(ctx, project) {
		return nil, &UpstreamError{Msg: project + " is not the top folder of a git checkout; --clone . needs one (or use run without --clone .)"}
	}
	proj := gitCmd{dir: project}
	head, branch, err := resolveHead(ctx, proj)
	if err != nil {
		return nil, err
	}
	up, err := resolveUpstream(ctx, proj, head, branch, toHTTPS)
	if err != nil {
		return nil, err
	}
	if st, err := proj.output(ctx, "status", "--porcelain", "-z", "--untracked-files=normal"); err == nil {
		up.Dirty = len(st) > 0
	}
	return up, nil
}

// LoopbackURL: the URL's host is localhost or a loopback address.
func LoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func resolveUpstream(ctx context.Context, proj gitCmd, head, branch string, toHTTPS func(string) (string, bool)) (*Upstream, error) {
	if head == "" {
		return nil, &UpstreamError{Msg: "this branch has no commit yet; use run without --clone ."}
	}
	short := strings.TrimPrefix(branch, "refs/heads/")
	if short == branch {
		short = ""
	}
	remote := ""
	if short != "" {
		remote = gitConfigLocal(ctx, proj, "branch."+short+".remote")
	}
	if remote == "" || remote == "." {
		remote = "origin"
	}
	raw := gitConfigLocal(ctx, proj, "remote."+remote+".url")
	if raw == "" {
		return nil, &UpstreamError{Msg: "this checkout has no remote " + remote + "; use run without --clone ."}
	}
	clean, ok := sanitizeRemoteURL(raw)
	if !ok {
		return nil, &UpstreamError{Msg: "remote " + remote + " is a local path; use run without --clone ."}
	}
	switch l := strings.ToLower(clean); {
	case strings.HasPrefix(l, "https://"):
	case strings.HasPrefix(l, "http://"):
		// The agent's credential helper would send the git token in clear
		// over the agent's egress (RV2 N7). A loopback address never
		// leaves the agent.
		if !LoopbackURL(clean) {
			return nil, &UpstreamError{Msg: "remote " + remote + " uses http://, which sends your git credentials unencrypted; --clone . needs an https remote (use run without --clone .)"}
		}
	default:
		// An ssh or scp-form address clones over https when a rewrite
		// covers it (B2 2.5): the agent has no SSH key, and the cluster
		// adds the credential only to https.
		h := ""
		if toHTTPS != nil {
			if v, ok := toHTTPS(clean); ok && strings.HasPrefix(strings.ToLower(v), "https://") {
				h = v
			}
		}
		if h == "" {
			return nil, &UpstreamError{Msg: "remote " + remote + " is an ssh address no https rewrite covers; ask your administrator to add it to substrate.git.https_rewrite, or use run without --clone ."}
		}
		clean = h
	}
	var cands []string
	if short != "" {
		if m := gitConfigLocal(ctx, proj, "branch."+short+".merge"); strings.HasPrefix(m, "refs/heads/") {
			cands = append(cands, "refs/remotes/"+remote+"/"+strings.TrimPrefix(m, "refs/heads/"))
		}
		cands = append(cands, "refs/remotes/"+remote+"/"+short)
	}
	cands = append(cands, "refs/remotes/"+remote+"/HEAD")
	up := &Upstream{Remote: remote, URL: clean}
	for _, ref := range cands {
		tip, err := proj.line(ctx, "rev-parse", "-q", "--verify", ref+"^{commit}")
		if err != nil || tip == "" {
			continue
		}
		base, err := proj.line(ctx, "merge-base", head, tip)
		if err != nil || base == "" {
			continue
		}
		if full, err := proj.line(ctx, "rev-parse", "--symbolic-full-name", ref); err == nil && full != "" {
			ref = full
		}
		up.Base, up.AtTip = base, tip == head
		up.Branch = strings.TrimPrefix(ref, "refs/remotes/"+remote+"/")
		break
	}
	if up.Base == "" {
		return nil, &UpstreamError{Msg: "this branch shares no commit with " + remote + "; use run without --clone ."}
	}
	n, err := proj.line(ctx, "rev-list", "--count", up.Base+".."+head)
	if err != nil {
		return nil, err
	}
	if up.Commits, err = strconv.Atoi(n); err != nil {
		return nil, fmt.Errorf("workspace: count unpushed commits: %q", n)
	}
	return up, nil
}

// FetchUpstream fetches the rest of the branch's history from the server
// into the uploaded copy in the sandbox. It runs the sandbox's own git
// config (the image's credential helper is what egress fills in), asks for
// a partial clone (no file contents until a command needs them) and falls
// back to a full fetch when the server refuses one. A copy without an
// upstream is returned unchanged.
func FetchUpstream(ctx context.Context, dataDir, name string, ex Execer) (*CopyRecord, error) {
	rec, err := LoadCopy(dataDir, name)
	if err != nil {
		return nil, err
	}
	up := rec.Upstream
	if up == nil {
		return rec, nil
	}
	script := strings.Join([]string{
		"set -u",
		"export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true SSH_ASKPASS=/bin/true LC_ALL=C",
		"G=" + shellQuote(rec.RemoteGitDir),
		"W=" + shellQuote(rec.RemoteDir),
		"R=" + shellQuote(up.Remote),
		`g() { git --git-dir="$G" --work-tree="$W" -c core.hooksPath=/dev/null -c core.fsmonitor=false -c protocol.file.allow=never -c protocol.ext.allow=never "$@"; }`,
		`U=; [ -f "$G/shallow" ] && U=--unshallow`,
		`if g fetch --quiet --filter=blob:none $U "$R"; then exit 0; fi`,
		`if g fetch --quiet $U "$R"; then exit 0; fi`,
		`exit 1`,
	}, "\n")
	res, err := ex.Exec(ctx, name, ExecRequest{Argv: []string{"sh", "-c", script}, Timeout: 15 * time.Minute, Idempotent: true})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("workspace: fetch the history of %s from %s in the sandbox (exit %d): %s", up.Branch, up.URL, res.ExitCode, stderrReason(res.Stderr))
	}
	return rec, nil
}
