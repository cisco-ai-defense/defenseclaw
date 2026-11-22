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

// B2 2.4: pull NAME --push-branch BR pushes the actor's work to its
// checkout's origin as a new branch, from inside the actor, with the
// credential the cluster binds to the git host (the image's credential
// helper answers with a placeholder that egress swaps). It never forces:
// BR is new on origin, or a branch this actor pushed before (then git
// refuses anything but a fast-forward).

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// PushPlaceholder is the value the actor image's credential helpers and
// config files carry in a credential's place (kit.PlaceholderSecret). A
// pushed change that writes it is flagged: it is no secret, but it means a
// config file now names a credential the repository should not hold (B1.9).
const PushPlaceholder = "placeholder-not-a-secret"

// BranchExec runs argv in the actor in dir and returns its output and exit
// code. (*Client).BranchExec is the relay's; tests run a local shell.
type BranchExec func(ctx context.Context, argv []string, dir string, env map[string]string, timeout time.Duration) (stdout, stderr string, code int, err error)

// BranchExec adapts the relay exec.
func (c *Client) BranchExec(ctx context.Context, argv []string, dir string, env map[string]string, timeout time.Duration) (string, string, int, error) {
	res, err := c.Exec(ctx, "", osw.ExecRequest{Argv: argv, Workdir: dir, Env: env, Timeout: timeout})
	if err != nil {
		return "", "", 0, err
	}
	return string(res.Stdout), string(res.Stderr), res.ExitCode, nil
}

// BranchPush is what pull --push-branch would push.
type BranchPush struct {
	// Dir is the checkout in the actor; URL its origin as git reads it;
	// Host and Repo the https host and path (team/app) it pushes to.
	Dir, URL, Host, Repo string
	// Head is the agent's HEAD; Commit what is pushed: Head, or a commit
	// of the agent's uncommitted work on Head when Made.
	Head, Commit string
	Made         bool
	// Commits counts the commits origin does not have; Files the paths they
	// change.
	Commits int
	Files   []string
	// Placeholder lists the files whose new lines carry PushPlaceholder;
	// RunsCode the ones that can run code (CI, hooks, scripts) where the
	// branch lands; Secrets the secret findings in the new lines.
	Placeholder []string
	RunsCode    []string
	Secrets     []osw.ScanFinding
}

// Flagged reports whether the push needs a careful look.
func (p *BranchPush) Flagged() bool {
	return len(p.Placeholder) > 0 || len(p.RunsCode) > 0 || len(p.Secrets) > 0
}

// BranchPushError is a push refusal in plain words.
type BranchPushError struct {
	// Kind is no_checkout, no_origin, no_commit, not_https, exists,
	// refused, mismatch or failed.
	Kind string
	Msg  string
}

func (e *BranchPushError) Error() string { return e.Msg }

const pushPrepareScript = `set -u
root=$1 label=$2
cd "$root" || exit 3
if [ ! -e .git ]; then
  n=0; d=
  for g in */.git; do [ -e "$g" ] && { n=$((n+1)); d=${g%/.git}; }; done
  [ "$n" -eq 1 ] || { echo "no single git checkout in $root" >&2; exit 3; }
  cd "$d" || exit 3
fi
url=$(git config --get remote.origin.url) || { echo "no origin remote" >&2; exit 4; }
head=$(git rev-parse -q --verify HEAD) || { echo "no commit" >&2; exit 5; }
commit=$head made=0
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  idx=$(mktemp -u) || exit 6
  trap 'rm -f "$idx" "$idx.lock"' EXIT
  GIT_INDEX_FILE=$idx git read-tree "$head" && GIT_INDEX_FILE=$idx git add -A . || exit 6
  tree=$(GIT_INDEX_FILE=$idx git write-tree) || exit 6
  if ! git var GIT_COMMITTER_IDENT >/dev/null 2>&1; then
    export GIT_AUTHOR_NAME="DefenseClaw agent $label" GIT_AUTHOR_EMAIL=agent@defenseclaw.invalid
    export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL=$GIT_AUTHOR_EMAIL
  fi
  commit=$(git commit-tree "$tree" -p "$head" -m "defenseclaw: work of agent $label") || exit 6
  made=1
fi
printf 'dir\t%s\nurl\t%s\nhead\t%s\ncommit\t%s\nmade\t%s\n' "$(pwd)" "$url" "$head" "$commit" "$made"
printf 'commits\t%s\n' "$(git rev-list --count "$commit" --not --remotes=origin)"
git log --format= --name-only "$commit" --not --remotes=origin | sort -u | sed 's/^/file\t/'
git log --format= --name-only -G"$3" "$commit" --not --remotes=origin | sort -u | sed 's/^/placeholder\t/'
`

const pushPatchScript = `git log -p --no-color --no-ext-diff --format= -U0 "$1" --not --remotes=origin`

const pushScript = `set -u
c=$1 b=$2
cur=$(git ls-remote --heads origin "refs/heads/$b") || { echo "ls-remote failed" >&2; exit 6; }
cur=${cur%%[[:space:]]*}
prev=$(git config --get "defenseclaw-push.$b.commit" || true)
if [ -n "$cur" ] && [ "$cur" != "$prev" ]; then echo "exists $cur" >&2; exit 7; fi
if [ -n "$cur" ] && ! git merge-base --is-ancestor "$cur" "$c" 2>/dev/null; then
  # The branch holds an earlier commit of the agent's uncommitted work,
  # which is not in the agent's history: join the two, so the branch
  # moves forward and nothing on it is lost.
  git cat-file -e "$cur^{commit}" 2>/dev/null || { echo "exists $cur" >&2; exit 7; }
  if ! git var GIT_COMMITTER_IDENT >/dev/null 2>&1; then
    export GIT_AUTHOR_NAME="DefenseClaw agent $3" GIT_AUTHOR_EMAIL=agent@defenseclaw.invalid
    export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL=$GIT_AUTHOR_EMAIL
  fi
  c=$(git commit-tree "$c^{tree}" -p "$cur" -p "$c" -m "defenseclaw: work of agent $3") || exit 8
fi
git -c core.hooksPath=/dev/null push --no-verify origin "$c:refs/heads/$b" >/dev/null || exit 8
got=$(git ls-remote --heads origin "refs/heads/$b") || exit 9
got=${got%%[[:space:]]*}
[ "$got" = "$c" ] || { echo "mismatch $got" >&2; exit 9; }
git config "defenseclaw-push.$b.commit" "$c"
printf 'pushed\t%s\n' "$c"
`

// pushEnv keeps git from prompting in the actor.
var pushEnv = map[string]string{"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/true", "SSH_ASKPASS": "/bin/true"}

// PrepareBranchPush reads, in the actor under root, the checkout pull
// --push-branch pushes: its origin, what origin does not have yet, and the
// flags of the review. The agent's uncommitted work is committed for the
// push with a private index, so the agent's HEAD and index do not move.
func PrepareBranchPush(ctx context.Context, run BranchExec, root, label string, rules []config.SubstrateGitRewrite) (*BranchPush, error) {
	out, stderr, code, err := run(ctx, []string{"sh", "-c", pushPrepareScript, "sh", root, label, PushPlaceholder}, root, pushEnv, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	switch code {
	case 0:
	case 3:
		return nil, &BranchPushError{Kind: "no_checkout", Msg: "the agent's folder is not a git checkout (or holds more than one), so there is no origin to push to; bring the work home with --branch NAME instead"}
	case 4:
		return nil, &BranchPushError{Kind: "no_origin", Msg: "the agent's checkout has no origin remote; bring the work home with --branch NAME instead"}
	case 5:
		return nil, &BranchPushError{Kind: "no_commit", Msg: "the agent's checkout has no commit yet"}
	default:
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the agent's checkout: " + lastLine(stderr, out)}
	}
	p := &BranchPush{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		switch k {
		case "dir":
			p.Dir = v
		case "url":
			p.URL = v
		case "head":
			p.Head = v
		case "commit":
			p.Commit = v
		case "made":
			p.Made = v == "1"
		case "commits":
			p.Commits, _ = strconv.Atoi(v)
		case "file":
			if v != "" {
				p.Files = append(p.Files, v)
				if osw.RunsCode(v) {
					p.RunsCode = append(p.RunsCode, v)
				}
			}
		case "placeholder":
			if v != "" {
				p.Placeholder = append(p.Placeholder, v)
			}
		}
	}
	host, repo := GitRemoteTarget(p.URL, rules)
	if host == "" || repo == "" {
		return nil, &BranchPushError{Kind: "not_https", Msg: "the agent's origin " + safeRemote(p.URL) +
			" is not an https address the cluster can add a credential for; ask your administrator to add it to substrate.git.https_rewrite, or bring the work home with --branch NAME"}
	}
	p.Host, p.Repo = host, repo
	if p.Commits > 0 {
		if patch, _, code, err := run(ctx, []string{"sh", "-c", pushPatchScript, "sh", p.Commit}, p.Dir, pushEnv, 2*time.Minute); err == nil && code == 0 {
			p.Secrets = scanAddedLines(patch)
		}
	}
	return p, nil
}

// scanAddedLines runs the secret rules on the lines each file's patch adds.
func scanAddedLines(patch string) []osw.ScanFinding {
	added := map[string]*strings.Builder{}
	var cur string
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			cur = strings.TrimPrefix(strings.TrimPrefix(line, "+++ "), "b/")
			if cur == "/dev/null" {
				cur = ""
			}
		case strings.HasPrefix(line, "+") && cur != "":
			b := added[cur]
			if b == nil {
				b = &strings.Builder{}
				added[cur] = b
			}
			b.WriteString(line[1:])
			b.WriteByte('\n')
		}
	}
	names := make([]string, 0, len(added))
	for n := range added {
		names = append(names, n)
	}
	sort.Strings(names)
	sc := osw.SecretsScanner()
	var out []osw.ScanFinding
	for _, n := range names {
		for _, f := range sc.ScanContent(n, []byte(added[n].String())) {
			out = append(out, osw.ScanFinding{Path: n, Scanner: sc.Name(), RuleID: f.RuleID, Severity: string(f.Severity), Title: f.Title, Location: f.Location})
		}
	}
	return out
}

// Push pushes p.Commit to origin's refs/heads/branch from the actor and
// checks with ls-remote that the branch is there. It never forces; a
// branch this actor pushed before moves forward only (p.Commit becomes
// what was pushed).
func (p *BranchPush) Push(ctx context.Context, run BranchExec, branch, name string) error {
	out, stderr, code, err := run(ctx, []string{"sh", "-c", pushScript, "sh", p.Commit, branch, name}, p.Dir, pushEnv, 10*time.Minute)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		for _, line := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(line, "pushed\t"); ok && v != "" {
				p.Commit = v
			}
		}
		return nil
	case 7:
		return &BranchPushError{Kind: "exists", Msg: "branch " + branch + " already exists on origin; pick a new name"}
	case 8:
		low := strings.ToLower(stderr)
		if strings.Contains(low, "non-fast-forward") || strings.Contains(low, "fetch first") || strings.Contains(low, "rejected") && !strings.Contains(low, "403") {
			return &BranchPushError{Kind: "exists", Msg: "branch " + branch + " on origin has commits the agent's work does not have; nothing was forced. Pick a new name"}
		}
		if strings.Contains(low, "403") || strings.Contains(low, "permission") || strings.Contains(low, "denied") ||
			strings.Contains(low, "authentication failed") || strings.Contains(low, "could not read username") {
			return &BranchPushError{Kind: "refused", Msg: fmt.Sprintf("%s refused the push: the credential the cluster binds to it cannot write to %s. "+
				"Ask your administrator for a token with write access, or push from your computer: defenseclaw substrate pull %s --branch %s",
				p.Host, p.Repo, name, branch)}
		}
		return &BranchPushError{Kind: "failed", Msg: "git could not push from the agent: " + lastLine(stderr, "")}
	case 9:
		return &BranchPushError{Kind: "mismatch", Msg: "the push finished, but origin's " + branch + " is not at the agent's commit " + short(p.Commit) +
			"; check the branch on " + p.Host + " before you open a pull request"}
	default:
		return &BranchPushError{Kind: "failed", Msg: "git could not push from the agent: " + lastLine(stderr, "")}
	}
}

func short(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// GitRemoteTarget is the https host and repository path (no .git) git
// pushes to for remote, after the baked rules plus rules
// (config.RewriteGitURL, the map CloneHost uses); "" when remote is not
// https after them.
func GitRemoteTarget(remote string, rules []config.SubstrateGitRewrite) (host, repo string) {
	raw := strings.TrimSpace(remote)
	if v, ok := config.RewriteGitURL(raw, rules); ok {
		raw = v
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", ""
	}
	repo = strings.TrimSuffix(strings.Trim(path.Clean("/"+u.Path), "/"), ".git")
	if repo == "" || repo == "." {
		return "", ""
	}
	return strings.ToLower(u.Host), repo
}

// safeRemote is remote without any user or password.
func safeRemote(remote string) string {
	if u, err := url.Parse(remote); err == nil && u.User != nil {
		u.User = nil
		return u.String()
	}
	return remote
}

// CompareLink is the page that opens a pull request for branch, for the
// hosts whose page form is known; "" for any other.
func CompareLink(host, repo, branch string) string {
	b := url.QueryEscape(branch)
	switch host {
	case "github.com":
		return "https://github.com/" + repo + "/compare/" + branch + "?expand=1"
	case "gitlab.com":
		return "https://gitlab.com/" + repo + "/-/merge_requests/new?merge_request%5Bsource_branch%5D=" + b
	case "bitbucket.org":
		return "https://bitbucket.org/" + repo + "/pull-requests/new?source=" + b
	}
	return ""
}
