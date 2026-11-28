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

// B2 2.4: pull NAME --push-branch BR pushes the actor's work as a new
// branch, from inside the actor, to the origin this computer recorded for
// the copy, with the credential the cluster binds to the git host (the
// image's credential helper answers with a placeholder that egress swaps). It never forces:
// BR is new on origin, or a branch this computer pushed before (then only
// a fast-forward).
//
// The agent can write its checkout's git config and refs, so the review
// and the push read neither (RV4). Where they go is the origin this
// computer recorded when it made the copy (RecordedOrigin: the --clone
// address, or the uploaded folder's origin from this computer's own git
// config), never a remote the actor's config names: a second
// remote.origin.url, pushurl, insteadOf, include or the agent's user config
// would otherwise choose it (GAP-0768, TST-5887). The review uses a scratch git directory,
// while the push builds a fresh bare repository from the reviewed commit's
// content-addressed objects. Both disable system and global Git config and
// explicitly use only the image-bound credential helper and CA bundle for
// HTTPS. They talk to the one HTTPS address the review names. What origin lacks comes from that address's ls-remote,
// and the "pushed before" record is kept on this computer.
//
// The agent can also write its object store's metadata (RV-SYNC5): a
// checkout that borrows objects (objects/info/alternates) is refused. The
// review's scratch directory reads the checkout's own loose objects and
// packs only (never its info/ files), then packs the full closure of the
// approved commit. The push copies only that pack into its fresh repository;
// snapshot HEAD, refs, config and objects/info are not used (GAP-0797/0810). The push moves origin's branch only from the state the
// review saw, with a lease that git and the server check (GAP-0798).
//
// A relay of the agent's user runs those steps as the agent, which could
// rewrite the review's scratch files, swap a loose object between the pack
// and the review, or edit the refs it reads, so the review could describe
// the commit wrongly (GAP-0795), and could rewrite the push repository's
// config between init and push (GAP-1073). A separated relay (root,
// relay.agent_user) therefore runs them itself (relay.GitCommand): only
// the pack of the commit is made as the agent's user, the relay checks
// every object against its id into a folder only it can write, and reviews
// and pushes that copy as its own user. A relay that cannot (not
// separated, or older) makes the launcher run the in-actor steps, with a
// warning before the review (BranchPush.Warning).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// pushReplacedPattern finds the placeholders an upload with replaced
// credentials (S9a) writes in a file (DC_SECRET_<n>, the pattern pull
// keeps out). git -G takes it as an extended regular expression.
const pushReplacedPattern = `DC_SECRET_[0-9][0-9]*`

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
	// Dir is the checkout in the actor; URL the origin this computer
	// recorded for the copy (never the actor's git config); Host and Repo
	// the https host and path (team/app) it pushes to, and PushURL the
	// exact address the review, the push and its checks use.
	Dir, URL, Host, Repo, PushURL string
	// Commit is the agent's HEAD, or a commit of its uncommitted work
	// on HEAD when Made.
	Commit string
	Made   bool
	// Commits counts the commits origin does not have; Files the paths they
	// change.
	Commits int
	Files   []string
	// Placeholder lists the files whose new lines carry kit.PlaceholderSecret (the value the
	// actor image's credential helpers carry in a credential's place);
	// RunsCode the ones that can run code (CI, hooks, scripts) where the
	// branch lands; Secrets the secret findings in the new lines.
	Placeholder []string
	RunsCode    []string
	Secrets     []osw.ScanFinding
	// objects is the checkout's object directory; snapshot is the actor
	// folder holding the review's full commit pack. The push imports only
	// that pack ("" once Discard removed it).
	objects, snapshot string
	// pack is the one self-contained pack made from reviewedCommit.
	// Commit may later become a merge with this computer's prior push.
	pack, reviewedCommit string
	// seen is origin's refs as the review read them (ref -> commit).
	seen map[string]string
	// Warning is said before the review when the actor's relay could not
	// run it as its own user (a relay of the agent's user, or one older
	// than this launcher): an agent process could then change what the
	// review reads (GAP-0795). "" when the relay ran it.
	Warning string
	// relayOwned: the relay holds the review's copy (snapshot is its
	// name) and pushes and discards it itself.
	relayOwned bool
}

// Flagged reports whether the push needs a careful look.
func (p *BranchPush) Flagged() bool {
	return len(p.Placeholder) > 0 || len(p.RunsCode) > 0 || len(p.Secrets) > 0
}

// BranchPushError is a push refusal in plain words.
type BranchPushError struct {
	// Kind is no_checkout, no_origin, no_commit, not_https, alternates,
	// objects, replaced_copy, exists, moved, refused, mismatch or failed.
	Kind string
	Msg  string
}

func (e *BranchPushError) Error() string { return e.Msg }

// pushPrepareScript finds the checkout and commits the agent's uncommitted
// work with a private index. It reads no remote: the origin comes from this
// computer's record. It prints NUL-ended key\tvalue records, so a newline
// in a folder name cannot add a key.
const pushPrepareScript = `set -u
root=$1 label=$2
cd "$root" || exit 3
if [ ! -e .git ]; then
  n=0; d=
  for g in */.git; do [ -e "$g" ] && { n=$((n+1)); d=${g%/.git}; }; done
  [ "$n" -eq 1 ] || { echo "no single git checkout in $root" >&2; exit 3; }
  cd "$d" || exit 3
fi
head=$(git rev-parse -q --verify HEAD) || { echo "no commit" >&2; exit 5; }
objs=$(cd "$(git rev-parse --git-path objects)" && pwd -P) || exit 6
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
printf 'dir\t%s\000commit\t%s\000made\t%s\000objects\t%s\000' "$(pwd)" "$commit" "$made" "$objs"
`

// The review and push scripts are the relay's (relay/gitpush.go): a
// separated relay runs them itself (relay.GitCommand, GAP-0795), and a
// relay of the agent's own user through the exec route, as the agent.
const (
	pushGit           = relay.GitPrelude
	pushReviewScript  = relay.GitReviewScript
	pushScript        = relay.GitPushScript
	pushDiscardScript = relay.GitDiscardScript
)

// pushEnv keeps git from prompting in the actor.
var pushEnv = map[string]string{"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/true", "SSH_ASKPASS": "/bin/true"}

// PrepareBranchPush reads, in the actor under root, the checkout pull
// --push-branch pushes: what origin does not have yet, and the flags of the
// review. origin is the address this computer recorded for the copy
// (RecordedOrigin); "" refuses, since the actor's own git config may name
// any repository. The agent's uncommitted work is committed for the
// push with a private index, so the agent's HEAD and index do not move.
// Reading what origin has is a network read (ls-remote); nothing is
// written anywhere.
func PrepareBranchPush(ctx context.Context, run BranchExec, root, label, origin string, rules []config.SubstrateGitRewrite) (*BranchPush, error) {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return nil, &BranchPushError{Kind: "no_origin", Msg: "this computer has no record of the agent's origin (the agent was not started here, " +
			"or its folder had no origin remote), and the address the agent's checkout names is the agent's to change; " +
			"bring the work home with --branch NAME and push it from your computer"}
	}
	out, stderr, code, err := run(ctx, []string{"sh", "-c", pushPrepareScript, "sh", root, label}, root, pushEnv, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	switch code {
	case 0:
	case 3:
		return nil, &BranchPushError{Kind: "no_checkout", Msg: "the agent's folder is not a git checkout (or holds more than one), so there is no origin to push to; bring the work home with --branch NAME instead"}
	case 5:
		return nil, &BranchPushError{Kind: "no_commit", Msg: "the agent's checkout has no commit yet"}
	default:
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the agent's checkout: " + lastLine(stderr, out)}
	}
	kv := pushRecords(out)
	p := &BranchPush{Dir: kv["dir"], URL: origin, Commit: kv["commit"], Made: kv["made"] == "1", objects: kv["objects"]}
	if p.Commit == "" || p.objects == "" {
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the agent's checkout: " + lastLine(stderr, out)}
	}
	p.Host, p.Repo, p.PushURL = GitRemoteTarget(p.URL, rules)
	if p.PushURL == "" {
		return nil, &BranchPushError{Kind: "not_https", Msg: "the origin " + safeRemote(p.URL) +
			" is not an https address the cluster can add a credential for; ask your administrator to add it to substrate.git.https_rewrite, or bring the work home with --branch NAME"}
	}
	out, stderr, code, err = run(ctx, []string{relay.GitCommand, "review", p.objects, p.PushURL, p.Commit, kit.PlaceholderSecret, pushReplacedPattern},
		p.Dir, pushEnv, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	p.relayOwned = true
	if code == relay.ExitGitUnseparated || code == relay.ExitNotRunnable || code == relay.ExitGitNoRootGit {
		p.relayOwned, p.Warning = false, unseparatedReview(code)
		out, stderr, code, err = run(ctx, []string{"sh", "-c", pushReviewScript, "sh", p.objects, p.PushURL, p.Commit, kit.PlaceholderSecret, pushReplacedPattern},
			p.Dir, pushEnv, 5*time.Minute)
		if err != nil {
			return nil, err
		}
	}
	switch code {
	case 0:
	case 11:
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the branches of " + p.PushURL + " from the agent: " + lastLine(stderr, "")}
	case 12:
		return nil, &BranchPushError{Kind: "alternates", Msg: "not pushed: the agent's checkout borrows objects from another store (" + lastLine(stderr, "") +
			"), and pull --push-branch pushes only what the checkout holds itself. Bring the work home with --branch NAME and push it from your computer"}
	case 13:
		return nil, &BranchPushError{Kind: "failed", Msg: "not pushed: the agent's checkout is missing objects its commits need: " + lastLine(stderr, "")}
	case relay.ExitGitObjects:
		return nil, &BranchPushError{Kind: "objects", Msg: "not pushed: the agent's checkout gave objects whose content does not match their ids, " +
			"or not every object of its commits (" + lastLine(stderr, "") + "). Bring the work home with --branch NAME and look at it on your computer"}
	default:
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the agent's commits: " + lastLine(stderr, "")}
	}
	parts, ok := pushFrames(out)
	if !ok {
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the agent's commits: the answer was cut short"}
	}
	p.snapshot = parts["snapshot"]
	p.pack = parts["pack"]
	p.reviewedCommit = p.Commit
	p.seen = pushRefs(parts["refs"])
	p.Commits, _ = strconv.Atoi(strings.TrimSpace(parts["commits"]))
	p.Files = pushNames(parts["file"])
	for _, f := range p.Files {
		if osw.RunsCode(f) {
			p.RunsCode = append(p.RunsCode, f)
		}
	}
	p.Placeholder = pushNames(parts["placeholder"])
	if r := pushNames(parts["replaced"]); len(r) > 0 {
		// The commits write the placeholders an upload with replaced
		// credentials put in the copy: pushed, they would replace the
		// person's lines upstream (RV6-4). This holds on any computer,
		// with or without the copy's record.
		p.Discard(ctx, run)
		return nil, &BranchPushError{Kind: "replaced_copy", Msg: "not pushed: the agent's commits put credential placeholders (DC_SECRET_<n>) in " +
			strings.Join(quoteNames(r, 3), ", ") + " where your credential lines were, so the push would replace them upstream. " +
			"Bring the work home with pull --branch NAME on the computer you ran the agent from, then push it from there"}
	}
	if p.Commits > 0 {
		p.Secrets = scanAddedLines(parts["patch"])
	}
	return p, nil
}

// unseparatedReview is the warning of a review the relay could not run as
// its own user (code is its answer to relay.GitCommand).
func unseparatedReview(code int) string {
	why := "the agent's relay runs as the agent's user (its template was built without relay.agent_user)"
	switch code {
	case relay.ExitNotRunnable:
		why = "the agent's relay is older than this computer's DefenseClaw"
	case relay.ExitGitNoRootGit:
		why = "the agent's image holds no git (or /bin/sh, or a program they use) that only root can change, so its relay will not run them as root"
	}
	return why + ", so the review below ran as the agent: an agent process could change what it shows. " +
		"The push still carries exactly the reviewed commit"
}

// pushRefs reads ls-remote output (commit\tref lines) into ref -> commit.
func pushRefs(raw string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		if c, ref, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok {
			if _, dup := m[ref]; !dup {
				m[ref] = c
			}
		}
	}
	return m
}

// Discard removes the review's copy of the objects in the actor, after
// the push or when nothing is pushed.
func (p *BranchPush) Discard(ctx context.Context, run BranchExec) {
	if p == nil || p.snapshot == "" {
		return
	}
	argv := []string{"sh", "-c", pushDiscardScript, "sh", p.snapshot}
	if p.relayOwned {
		argv = []string{relay.GitCommand, "discard", p.snapshot}
	}
	_, _, _, _ = run(ctx, argv, p.Dir, pushEnv, time.Minute)
	p.snapshot = ""
}

// pushRecords reads NUL-ended key\tvalue records; the first of a key wins.
func pushRecords(out string) map[string]string {
	kv := map[string]string{}
	for _, tok := range strings.Split(out, "\x00") {
		if k, v, ok := strings.Cut(tok, "\t"); ok {
			if _, dup := kv[k]; !dup {
				kv[k] = v
			}
		}
	}
	return kv
}

// pushFrames reads the "NAME LENGTH\0" frames of pushReviewScript; false
// when the output does not end on a whole frame.
func pushFrames(out string) (map[string]string, bool) {
	parts := map[string]string{}
	for out != "" {
		hdr, rest, ok := strings.Cut(out, "\x00")
		name, ln, ok2 := strings.Cut(hdr, " ")
		n, err := strconv.Atoi(ln)
		if !ok || !ok2 || err != nil || n < 0 || n > len(rest) {
			return nil, false
		}
		parts[name], out = rest[:n], rest[n:]
	}
	return parts, true
}

// pushNames is the sorted, distinct names of NUL-ended git -z output.
func pushNames(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range strings.Split(raw, "\x00") {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// quoteNames is at most n names, Go-quoted when they hold a character a
// terminal would act on, then "N more".
func quoteNames(names []string, n int) []string {
	var out []string
	for i, name := range names {
		if i == n {
			out = append(out, fmt.Sprintf("%d more", len(names)-n))
			break
		}
		out = append(out, DisplayName(name))
	}
	return out
}

// DisplayName is a file name as the review prints it: as it is when every
// character is printable, else Go-quoted, so a name cannot move the
// cursor or write terminal controls.
func DisplayName(name string) string {
	if !utf8.ValidString(name) || strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return strconv.Quote(name)
	}
	return name
}

// scanAddedLines runs the secret rules on the lines each file's patch adds.
// A header name git quotes (a control character, a quote or a backslash
// in it) is unquoted, so the rules see the real name.
func scanAddedLines(patch string) []osw.ScanFinding {
	added := map[string]*strings.Builder{}
	var cur string
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			cur = strings.TrimPrefix(line, "+++ ")
			if strings.HasPrefix(cur, `"`) {
				if u, err := strconv.Unquote(cur); err == nil {
					cur = u
				}
			}
			cur = strings.TrimPrefix(cur, "b/")
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

// Push pushes p.Commit to refs/heads/branch of p.PushURL from the actor,
// with the objects the review copied, and checks with ls-remote that the
// branch is there. prev is the commit this computer pushed to that branch
// before (PushedBefore), "" for none. It never forces: a branch origin has
// moves only when it is at prev, and then forward only (p.Commit becomes
// what was pushed); and only from the state the review saw.
func (p *BranchPush) Push(ctx context.Context, run BranchExec, branch, name, prev string) error {
	if p.snapshot == "" || p.pack == "" {
		return &BranchPushError{Kind: "failed", Msg: "not pushed: the review's copy of the agent's commits is gone; run pull --push-branch again"}
	}
	seen := p.seen["refs/heads/"+branch]
	argv := []string{"sh", "-c", pushScript, "sh", p.snapshot, p.PushURL, p.reviewedCommit, branch, name, prev, seen, p.pack}
	if p.relayOwned {
		// The relay pushes its own copy as its own user (GAP-0795, GAP-1073).
		argv = []string{relay.GitCommand, "push", p.snapshot, p.PushURL, p.reviewedCommit, branch, name, prev, seen, p.pack}
	}
	out, stderr, code, err := run(ctx, argv, p.Dir, pushEnv, 10*time.Minute)
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
	case 10:
		return p.moved(branch, name)
	case 8:
		low := strings.ToLower(stderr)
		if strings.Contains(low, "stale info") {
			return p.moved(branch, name)
		}
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

// moved is the refusal when origin's branch is not where the review saw it.
func (p *BranchPush) moved(branch, name string) error {
	return &BranchPushError{Kind: "moved", Msg: "not pushed: branch " + branch + " on origin changed after the review, so nothing was pushed. " +
		"Run defenseclaw substrate pull " + name + " --push-branch " + branch + " again to review it as it is now"}
}

func short(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// GitRemoteTarget is the https host, repository path (no .git) and push
// address for remote, after the baked rules plus rules
// (config.RewriteGitURL, the map CloneHost uses); all "" when remote is not
// https after them. The address is https://HOST/PATH with the path as the
// remote has it (.git kept), without user, query or fragment.
func GitRemoteTarget(remote string, rules []config.SubstrateGitRewrite) (host, repo, pushURL string) {
	raw := strings.TrimSpace(remote)
	if v, ok := config.RewriteGitURL(raw, rules); ok {
		raw = v
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", "", ""
	}
	p := strings.Trim(path.Clean("/"+u.Path), "/")
	repo = strings.TrimSuffix(p, ".git")
	if repo == "" || repo == "." {
		return "", "", ""
	}
	host = strings.ToLower(u.Host)
	return host, repo, (&url.URL{Scheme: "https", Host: host, Path: "/" + p}).String()
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

// RecordedOrigin is the origin this computer recorded when it made the
// copy name: the run --clone address, or the uploaded folder's origin as
// this computer's own git config had it (credential-free). When both
// records exist, the newer one counts. "" when this computer has none.
// It never reads the actor, whose git config the agent can write (GAP-0768).
func RecordedOrigin(dataDir, name string) string {
	up, uerr := osw.LoadCopy(dataDir, name)
	hr, herr := loadHostRecord(dataDir, name)
	haveUp, haveClone := uerr == nil && up != nil, herr == nil && hr.CloneURL != ""
	switch {
	case haveClone && (!haveUp || up.UploadedAt == nil || !hr.UploadedAt.Before(*up.UploadedAt)):
		return strings.TrimSpace(hr.CloneURL)
	case haveUp:
		return strings.TrimSpace(up.Remotes["origin"])
	}
	return ""
}

// --- the "pushed before" record, on this computer --------------------------

// pushedPath keeps, per copy name, the commit this computer last pushed
// to each branch. It lives outside the actor, which can write its own git
// config and refs (RV4-2).
func pushedPath(dataDir, name string) string {
	return filepath.Join(dataDir, "substrate", "pushed", name+".json")
}

func pushedKey(host, repo, branch string) string { return host + "/" + repo + " refs/heads/" + branch }

func loadPushed(dataDir, name string) map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(pushedPath(dataDir, name)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// PushedBefore is the commit this computer last pushed with pull
// --push-branch to branch of host/repo for the copy name; "" for none.
func PushedBefore(dataDir, name, host, repo, branch string) string {
	return loadPushed(dataDir, name)[pushedKey(host, repo, branch)]
}

// RecordPushed saves commit as the last push to branch of host/repo.
func RecordPushed(dataDir, name, host, repo, branch, commit string) error {
	m := loadPushed(dataDir, name)
	m[pushedKey(host, repo, branch)] = commit
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	dst := pushedPath(dataDir, name)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(dst), name+".*.tmp")
	if err != nil {
		return err
	}
	_, werr := f.Write(append(b, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(f.Name(), dst)
	}
	if werr != nil {
		_ = os.Remove(f.Name())
	}
	return werr
}
