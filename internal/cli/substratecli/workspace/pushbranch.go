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
}

// Flagged reports whether the push needs a careful look.
func (p *BranchPush) Flagged() bool {
	return len(p.Placeholder) > 0 || len(p.RunsCode) > 0 || len(p.Secrets) > 0
}

// BranchPushError is a push refusal in plain words.
type BranchPushError struct {
	// Kind is no_checkout, no_origin, no_commit, not_https, alternates,
	// replaced_copy, exists, moved, refused, mismatch or failed.
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

// pushGit is the start of the review and push scripts: no repository or
// system or user config, no templates, hooks, replace refs, commit-graph,
// multi-pack index or bitmaps, so nothing in the checkout changes where
// the push goes, what it carries, or what the review sees. The only
// credential and TLS settings are image-bound paths from kit; no actor
// config is parsed for them. Nothing in the environment the relay passes
// on runs a command or changes the transport either: the ssh, proxy,
// password-prompt and exec-path variables and every trace (GIT_CURL_VERBOSE
// and GIT_TRACE_CURL would log the request headers) are unset, and https is
// the only protocol (RV-T6A); so are every GIT_SSL_* variable (client
// certificate and key, ciphers, version, CA), the proxy auth method, and
// GIT_COMMON_DIR and GIT_ATTR_SOURCE, which would move the refs, config and
// objects or the attributes the review reads (RV-T6B). g runs git.
const pushGit = `set -u
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_CONFIG_SYSTEM GIT_NAMESPACE GIT_TEMPLATE_DIR GIT_REPLACE_REF_BASE GIT_COMMON_DIR GIT_ATTR_SOURCE
unset GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT GIT_PROXY_COMMAND GIT_EXEC_PATH GIT_CURL_VERBOSE GIT_ALLOW_PROTOCOL GIT_PROTOCOL_FROM_USER GIT_HTTP_PROXY_AUTHMETHOD GIT_ASKPASS SSH_ASKPASS
for v in $(env | sed -n -e 's/^\(GIT_TRACE[A-Za-z0-9_]*\)=.*/\1/p' -e 's/^\(GIT_SSL_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$v"; done
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 GIT_ALLOW_PROTOCOL=https
g() { git -c core.quotePath=false -c core.hooksPath=/dev/null -c core.commitGraph=false -c core.multiPackIndex=false -c pack.useBitmaps=false -c credential.helper=` + kit.CredHelper + ` -c credential.useHttpPath=false -c http.sslCAInfo=` + kit.TrustBundle + ` "$@"; }
`

// pushReviewScript lists what origin lacks and makes the review pack
// ($snap, printed as the "snapshot" frame): a bare git directory g whose
// pack holds every object reachable from the approved commit. Its one
// alternate, v, views only the checkout's loose object folders and packs
// during review; the agent's objects/info files are never read. The later
// push copies only the named pack into a fresh repository. A checkout that borrows objects is refused
// (exit 12). ls-remote of the push address gives the commits origin has
// (the "refs" frame), and the range is the pushed commit ($3) without
// those the checkout holds. Names come NUL-ended (-z), so git quotes none
// of them. Each part goes out as a frame "NAME LENGTH\0" and LENGTH
// bytes, so no file name can end a part early. A merge is diffed against
// its first parent (--diff-merges=first-parent, git 2.31+), so content
// that only the merge commit adds is listed, flagged and scanned.
const pushReviewScript = pushGit + `objs=$1 url=$2 c=$3
for f in alternates http-alternates; do
  [ -e "$objs/info/$f" ] && [ -n "$(tr -d ' \t\r\n' < "$objs/info/$f" 2>/dev/null)" ] && { echo "objects/info/$f" >&2; exit 12; }
done
s=$(mktemp -d) && snap=$(mktemp -d) || exit 6
ok=0
trap 'rm -rf "$s"; [ "$ok" = 1 ] || rm -rf "$snap"' EXIT
mkdir -p "$snap/v/info" || exit 6
[ -d "$objs/pack" ] && { ln -s "$objs/pack" "$snap/v/pack" || exit 6; }
for d in "$objs"/[0-9a-f][0-9a-f]; do [ -d "$d" ] && { ln -s "$d" "$snap/v/" || exit 6; }; done
git init -q --bare --template= "$snap/g" || exit 6
printf '%s\n' "$snap/v" > "$snap/g/objects/info/alternates" || exit 6
export GIT_DIR=$snap/g
g ls-remote "$url" > "$s/refs" || exit 11
{ printf '%s\n' "$c"; cut -f1 "$s/refs" | sort -u | g cat-file --batch-check='%(objectname) %(objecttype)' |
  awk '$2 == "commit" || $2 == "tag" { print "^" $1 }'; } > "$s/range" || exit 6
g rev-list --count --stdin < "$s/range" > "$s/commits" || exit 6
# Pack the full closure of the reviewed commit. The later push must not
# borrow parent objects from the agent's writable checkout or its alternates.
pack=$(printf '%s\n' "$c" | g pack-objects --revs -q "$snap/g/objects/pack/pack") || exit 13
printf '%s' "$pack" > "$s/pack"
names() { g log --diff-merges=first-parent --format= --name-only -z --no-renames "$@" --stdin < "$s/range"; }
names > "$s/file" || exit 6
names -G"$4" > "$s/placeholder" || exit 6
names -G"$5" > "$s/replaced" || exit 6
: > "$s/patch"
[ "$(cat "$s/commits")" = 0 ] || g log -p --diff-merges=first-parent --no-color --no-ext-diff --no-textconv --no-renames --format= -U0 --stdin < "$s/range" > "$s/patch" || exit 6
printf '%s' "$snap" > "$s/snapshot"
for f in commits file placeholder replaced patch refs snapshot pack; do
  printf '%s %s\000' "$f" "$(wc -c < "$s/$f" | tr -d ' ')" && cat "$s/$f" || exit 6
done
ok=1
`

// pushScript pushes $3 to refs/heads/$4 from a fresh bare repository
// containing only the review's named pack ($1, $8); Discard removes the
// review copy. $6 is the commit this
// computer pushed to that branch before ("" for none): a branch origin has
// is refused unless it is at that commit. $7 is the branch as the review
// saw it ("" for none): the push is refused when origin's branch is not
// there now (exit 10), and it carries a lease on that state, so a writer
// that moves the branch during the push makes git or the server refuse it.
const pushScript = pushGit + `snap=$1 url=$2 c=$3 b=$4 label=$5 prev=$6 seen=$7
pack=$8
case "$pack" in ''|*[!0-9a-f]*) echo "bad reviewed pack id" >&2; exit 6;; esac
umask 077
s=$(mktemp -d) || exit 6
trap 'rm -rf "$s"' EXIT
git init -q --bare --template= "$s/g" || exit 6
src=$snap/g/objects/pack/pack-$pack
[ -f "$src.pack" ] && [ -f "$src.idx" ] || { echo "the review's pack is gone" >&2; exit 6; }
cp -- "$src.pack" "$src.idx" "$s/g/objects/pack/" || exit 6
export GIT_DIR=$s/g
# The copied pack is content-addressed. Verify the exact approved commit
# and every reachable object before any network write.
g fsck --strict --no-reflogs --no-progress "$c" >/dev/null 2>&1 ||
  { echo "the review's objects changed or are incomplete" >&2; exit 6; }
heads() { g ls-remote --heads "$url" > "$s/heads" && awk -v r="refs/heads/$b" '$2 == r { print $1; exit }' "$s/heads"; }
cur=$(heads) || { echo "ls-remote failed" >&2; exit 6; }
if [ -n "$cur" ] && [ "$cur" != "$prev" ]; then echo "exists $cur" >&2; exit 7; fi
[ "$cur" = "$seen" ] || { echo "moved ${cur:-gone}" >&2; exit 10; }
if [ -n "$cur" ] && ! g merge-base --is-ancestor "$cur" "$c" 2>/dev/null; then
  # The branch holds this computer's earlier push of the agent's
  # uncommitted work, which is not in the agent's history: join the two,
  # so the branch moves forward and nothing on it is lost.
  # A prior approved push of uncommitted work may not be an ancestor of
  # this review's commit. Obtain that exact branch tip from origin.
  g fetch -q --no-tags "$url" "refs/heads/$b" || exit 8
  g cat-file -e "$cur^{commit}" 2>/dev/null || { echo "moved ${cur:-gone}" >&2; exit 10; }
  export GIT_AUTHOR_NAME="DefenseClaw agent $label" GIT_AUTHOR_EMAIL=agent@defenseclaw.invalid
  export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL=$GIT_AUTHOR_EMAIL
  c=$(g commit-tree "$c^{tree}" -p "$cur" -p "$c" -m "defenseclaw: work of agent $label") || exit 8
fi
g push --no-verify --no-follow-tags --no-recurse-submodules --force-with-lease="refs/heads/$b:$seen" "$url" "$c:refs/heads/$b" >/dev/null || exit 8
got=$(heads) || exit 9
[ "$got" = "$c" ] || { echo "mismatch $got" >&2; exit 9; }
printf 'pushed\t%s\n' "$c"
`

// pushDiscardScript removes the review's copy when nothing is pushed.
const pushDiscardScript = `rm -rf -- "$1"`

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
	out, stderr, code, err = run(ctx, []string{"sh", "-c", pushReviewScript, "sh", p.objects, p.PushURL, p.Commit, kit.PlaceholderSecret, pushReplacedPattern},
		p.Dir, pushEnv, 5*time.Minute)
	if err != nil {
		return nil, err
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
	_, _, _, _ = run(ctx, []string{"sh", "-c", pushDiscardScript, "sh", p.snapshot}, p.Dir, pushEnv, time.Minute)
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
	out, stderr, code, err := run(ctx, []string{"sh", "-c", pushScript, "sh", p.snapshot, p.PushURL, p.reviewedCommit, branch, name, prev, seen, p.pack}, p.Dir, pushEnv, 10*time.Minute)
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
