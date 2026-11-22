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
// BR is new on origin, or a branch this computer pushed before (then only
// a fast-forward).
//
// The agent can write its checkout's git config and refs, so the review
// and the push read neither (RV4): they run in a scratch git directory
// over the checkout's objects, with the image's system config only, and
// talk to the one https address the review names. What origin lacks comes
// from that address's ls-remote, and the "pushed before" record is kept on
// this computer.

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
)

// PushPlaceholder is the value the actor image's credential helpers and
// config files carry in a credential's place (kit.PlaceholderSecret). A
// pushed change that writes it is flagged: it is no secret, but it means a
// config file now names a credential the repository should not hold (B1.9).
const PushPlaceholder = "placeholder-not-a-secret"

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
	// Dir is the checkout in the actor; URL its origin as git reads it;
	// Host and Repo the https host and path (team/app) it pushes to, and
	// PushURL the exact address the review, the push and its checks use.
	Dir, URL, Host, Repo, PushURL string
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
	// objects is the checkout's object directory, which the scratch git
	// directory of the push reads.
	objects string
}

// Flagged reports whether the push needs a careful look.
func (p *BranchPush) Flagged() bool {
	return len(p.Placeholder) > 0 || len(p.RunsCode) > 0 || len(p.Secrets) > 0
}

// BranchPushError is a push refusal in plain words.
type BranchPushError struct {
	// Kind is no_checkout, no_origin, no_commit, not_https, replaced_copy,
	// exists, refused, mismatch or failed.
	Kind string
	Msg  string
}

func (e *BranchPushError) Error() string { return e.Msg }

// pushPrepareScript finds the checkout and commits the agent's uncommitted
// work with a private index. It prints NUL-ended key\tvalue records, so a
// newline in a folder name or in the agent's remote cannot add a key.
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
printf 'dir\t%s\000url\t%s\000head\t%s\000commit\t%s\000made\t%s\000objects\t%s\000' "$(pwd)" "$url" "$head" "$commit" "$made" "$objs"
`

// pushScratch is the start of the review and push scripts: a scratch git
// directory over the checkout's objects ($1), with no repository or user
// config, no templates, no hooks and no replace refs, so nothing the agent
// set in its checkout changes where the push goes, what it carries, or
// what the review sees. g runs git there.
const pushScratch = `set -u
objs=$1 url=$2
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_NAMESPACE GIT_TEMPLATE_DIR GIT_REPLACE_REF_BASE
export GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1
s=$(mktemp -d) || exit 6
trap 'rm -rf "$s"' EXIT
git init -q --bare --template= "$s/g" || exit 6
export GIT_DIR=$s/g GIT_OBJECT_DIRECTORY=$objs
g() { git -c core.quotePath=false -c core.hooksPath=/dev/null "$@"; }
`

// pushReviewScript lists what origin lacks: ls-remote of the push address
// gives the commits origin has, and the range is the pushed commit ($3)
// without those the checkout holds. Names come NUL-ended (-z), so git
// quotes none of them. Each part goes out as a frame "NAME LENGTH\0" and
// LENGTH bytes, so no file name can end a part early.
const pushReviewScript = pushScratch + `c=$3
g ls-remote "$url" > "$s/refs" || exit 11
{ printf '%s\n' "$c"; cut -f1 "$s/refs" | sort -u | g cat-file --batch-check='%(objectname) %(objecttype)' |
  awk '$2 == "commit" || $2 == "tag" { print "^" $1 }'; } > "$s/range" || exit 6
g rev-list --count --stdin < "$s/range" > "$s/commits" || exit 6
names() { g log --format= --name-only -z --no-renames "$@" --stdin < "$s/range"; }
names > "$s/file" || exit 6
names -G"$4" > "$s/placeholder" || exit 6
names -G"$5" > "$s/replaced" || exit 6
: > "$s/patch"
[ "$(cat "$s/commits")" = 0 ] || g log -p --no-color --no-ext-diff --no-textconv --no-renames --format= -U0 --stdin < "$s/range" > "$s/patch" || exit 6
for f in commits file placeholder replaced patch; do
  printf '%s %s\000' "$f" "$(wc -c < "$s/$f" | tr -d ' ')" && cat "$s/$f" || exit 6
done
`

// pushScript pushes $3 to refs/heads/$4 of the push address. $6 is the
// commit this computer pushed to that branch before ("" for none): a
// branch origin has is refused unless it is at that commit.
const pushScript = pushScratch + `c=$3 b=$4 label=$5 prev=$6
heads() { g ls-remote --heads "$url" > "$s/heads" && awk -v r="refs/heads/$b" '$2 == r { print $1; exit }' "$s/heads"; }
cur=$(heads) || { echo "ls-remote failed" >&2; exit 6; }
if [ -n "$cur" ] && [ "$cur" != "$prev" ]; then echo "exists $cur" >&2; exit 7; fi
if [ -n "$cur" ] && ! g merge-base --is-ancestor "$cur" "$c" 2>/dev/null; then
  # The branch holds this computer's earlier push of the agent's
  # uncommitted work, which is not in the agent's history: join the two,
  # so the branch moves forward and nothing on it is lost.
  g cat-file -e "$cur^{commit}" 2>/dev/null || { echo "exists $cur" >&2; exit 7; }
  export GIT_AUTHOR_NAME="DefenseClaw agent $label" GIT_AUTHOR_EMAIL=agent@defenseclaw.invalid
  export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL=$GIT_AUTHOR_EMAIL
  c=$(g commit-tree "$c^{tree}" -p "$cur" -p "$c" -m "defenseclaw: work of agent $label") || exit 8
fi
g push --no-verify --no-follow-tags --no-recurse-submodules "$url" "$c:refs/heads/$b" >/dev/null || exit 8
got=$(heads) || exit 9
[ "$got" = "$c" ] || { echo "mismatch $got" >&2; exit 9; }
printf 'pushed\t%s\n' "$c"
`

// pushEnv keeps git from prompting in the actor.
var pushEnv = map[string]string{"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/true", "SSH_ASKPASS": "/bin/true"}

// PrepareBranchPush reads, in the actor under root, the checkout pull
// --push-branch pushes: its origin, what origin does not have yet, and the
// flags of the review. The agent's uncommitted work is committed for the
// push with a private index, so the agent's HEAD and index do not move.
// Reading what origin has is a network read (ls-remote); nothing is
// written anywhere.
func PrepareBranchPush(ctx context.Context, run BranchExec, root, label string, rules []config.SubstrateGitRewrite) (*BranchPush, error) {
	out, stderr, code, err := run(ctx, []string{"sh", "-c", pushPrepareScript, "sh", root, label}, root, pushEnv, 2*time.Minute)
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
	kv := pushRecords(out)
	p := &BranchPush{Dir: kv["dir"], URL: kv["url"], Head: kv["head"], Commit: kv["commit"], Made: kv["made"] == "1", objects: kv["objects"]}
	if p.Commit == "" || p.objects == "" {
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the agent's checkout: " + lastLine(stderr, out)}
	}
	p.Host, p.Repo, p.PushURL = GitRemoteTarget(p.URL, rules)
	if p.PushURL == "" {
		return nil, &BranchPushError{Kind: "not_https", Msg: "the agent's origin " + safeRemote(p.URL) +
			" is not an https address the cluster can add a credential for; ask your administrator to add it to substrate.git.https_rewrite, or bring the work home with --branch NAME"}
	}
	out, stderr, code, err = run(ctx, []string{"sh", "-c", pushReviewScript, "sh", p.objects, p.PushURL, p.Commit, PushPlaceholder, pushReplacedPattern},
		p.Dir, pushEnv, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	switch code {
	case 0:
	case 11:
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the branches of " + p.PushURL + " from the agent: " + lastLine(stderr, "")}
	default:
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the agent's commits: " + lastLine(stderr, "")}
	}
	parts, ok := pushFrames(out)
	if !ok {
		return nil, &BranchPushError{Kind: "failed", Msg: "could not read the agent's commits: the answer was cut short"}
	}
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
		return nil, &BranchPushError{Kind: "replaced_copy", Msg: "not pushed: the agent's commits put credential placeholders (DC_SECRET_<n>) in " +
			strings.Join(quoteNames(r, 3), ", ") + " where your credential lines were, so the push would replace them upstream. " +
			"Bring the work home with pull --branch NAME on the computer you ran the agent from, then push it from there"}
	}
	if p.Commits > 0 {
		p.Secrets = scanAddedLines(parts["patch"])
	}
	return p, nil
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

// Push pushes p.Commit to refs/heads/branch of p.PushURL from the actor and
// checks with ls-remote that the branch is there. prev is the commit this
// computer pushed to that branch before (PushedBefore), "" for none. It
// never forces: a branch origin has moves only when it is at prev, and
// then forward only (p.Commit becomes what was pushed).
func (p *BranchPush) Push(ctx context.Context, run BranchExec, branch, name, prev string) error {
	out, stderr, code, err := run(ctx, []string{"sh", "-c", pushScript, "sh", p.objects, p.PushURL, p.Commit, branch, name, prev}, p.Dir, pushEnv, 10*time.Minute)
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
