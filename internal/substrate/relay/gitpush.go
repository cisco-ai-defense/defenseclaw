// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import "github.com/defenseclaw/defenseclaw/internal/substrate/kit"

// The review and push of pull --push-branch (B2 2.4). They are the relay's
// fixed scripts: the launcher names an operation and its values, never the
// script a root relay runs.
//
// A relay of the agent's own user runs them through the exec route, as the
// agent (GitReviewScript, GitPushScript), and the launcher warns that an
// agent process could change what the review reads (GAP-0795). A separated
// relay (root, relay.agent_user set) runs them itself when an exec request
// names GitCommand: the agent's user only packs the commit out of its
// checkout (gitPackScript), the relay checks every object against its id
// (git index-pack --strict) into a folder only the relay can write, and the
// review and the push read and send only that copy, as the relay's user,
// with an environment of the relay's own (gitRelayEnv: programs only root
// can change, HOME in the relay's folder). So the agent can neither show
// the review content other than what is pushed, nor edit the refs, config
// or attributes the review reads, nor rewrite the push repository's config
// between init and push (GAP-1073), nor have root run a program it wrote.
const (
	// GitCommand is the argv[0] of an exec request that asks a separated
	// relay to run a git operation of its own: review OBJECTS URL COMMIT
	// PLACEHOLDER REPLACED, push SNAPSHOT URL COMMIT BRANCH LABEL PREV SEEN
	// PACK, or discard SNAPSHOT. A relay that predates it answers
	// ExitNotRunnable (no such program).
	GitCommand = "defenseclaw-relay-git"
	// ExitGitUnseparated is the answer of a relay of the agent's own user:
	// a review it ran would be no safer than the in-actor scripts.
	ExitGitUnseparated = 96
	// ExitGitNoRootGit is the answer of a separated relay whose image holds
	// no git, /bin/sh or program they use that only root can change
	// (gitRelayEnv): it will not run them as root, and the launcher runs
	// the in-actor scripts as the agent, with a warning, as for 96.
	ExitGitNoRootGit = 95
	// ExitGitObjects is a pack whose objects do not match their ids, or
	// that lacks some of the commit's objects (index-pack, fsck).
	ExitGitObjects = 14
)

// GitPrelude starts every review and push script: no repository or
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
// objects or the attributes the review reads (RV-T6B). No attributes file
// is read but the repository's own (core.attributesFile=/dev/null,
// GIT_ATTR_NOSYSTEM): one in the agent's HOME or XDG_CONFIG_HOME could mark
// every file binary ("-diff"), which empties the patch and the -G scans
// (GAP-0795 H2). g runs git.
const GitPrelude = `set -u
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_CONFIG_SYSTEM GIT_NAMESPACE GIT_TEMPLATE_DIR GIT_REPLACE_REF_BASE GIT_COMMON_DIR GIT_ATTR_SOURCE
unset GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT GIT_PROXY_COMMAND GIT_EXEC_PATH GIT_CURL_VERBOSE GIT_ALLOW_PROTOCOL GIT_PROTOCOL_FROM_USER GIT_HTTP_PROXY_AUTHMETHOD GIT_ASKPASS SSH_ASKPASS
for v in $(env | sed -n -e 's/^\(GIT_TRACE[A-Za-z0-9_]*\)=.*/\1/p' -e 's/^\(GIT_SSL_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$v"; done
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 GIT_ALLOW_PROTOCOL=https
g() { git -c core.quotePath=false -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c core.commitGraph=false -c core.multiPackIndex=false -c pack.useBitmaps=false -c credential.helper=` + kit.CredHelper + ` -c credential.useHttpPath=false -c http.sslCAInfo=` + kit.TrustBundle + ` "$@"; }
`

// gitRefuseAlternates refuses a checkout ($objs) that borrows objects
// (exit 12): only what the checkout holds itself is pushed (RV-SYNC5).
const gitRefuseAlternates = `for f in alternates http-alternates; do
  [ -e "$objs/info/$f" ] && [ -n "$(tr -d ' \t\r\n' < "$objs/info/$f" 2>/dev/null)" ] && { echo "objects/info/$f" >&2; exit 12; }
done
`

// gitCheckoutView makes $snap/g, a bare git directory whose one alternate,
// $snap/v, views only the checkout's loose object folders and packs; the
// agent's objects/info files are never read.
const gitCheckoutView = `mkdir -p "$snap/v/info" || exit 6
[ -d "$objs/pack" ] && { ln -s "$objs/pack" "$snap/v/pack" || exit 6; }
for d in "$objs"/[0-9a-f][0-9a-f]; do [ -d "$d" ] && { ln -s "$d" "$snap/v/" || exit 6; }; done
git init -q --bare --template= "$snap/g" || exit 6
printf '%s\n' "$snap/v" > "$snap/g/objects/info/alternates" || exit 6
export GIT_DIR=$snap/g
`

// gitReviewTail lists what origin lacks for the review, in $s: origin's
// refs ($s/refs, from ls-remote of the push address) give the commits it
// has, and the range is the pushed commit ($c) without those the
// repository holds. Names come NUL-ended (-z), so git quotes none of them.
// Each part goes out as a frame "NAME LENGTH\0" and LENGTH bytes, so no
// file name can end a part early. A merge is diffed against its first
// parent (--diff-merges=first-parent, git 2.31+), so content that only the
// merge commit adds is listed, flagged and scanned. $ph and $rp are the
// placeholder patterns (git -G, extended regular expressions); the scans
// read binary files as text (--text), so a NUL byte in a file does not hide
// a placeholder from the flags (GAP-0795). $s/pack and $s/snapshot are
// written before.
const gitReviewTail = `{ printf '%s\n' "$c"; cut -f1 "$s/refs" | sort -u | g cat-file --batch-check='%(objectname) %(objecttype)' |
  awk '$2 == "commit" || $2 == "tag" { print "^" $1 }'; } > "$s/range" || exit 6
g rev-list --count --stdin < "$s/range" > "$s/commits" || exit 6
names() { g log --diff-merges=first-parent --format= --name-only -z --no-renames "$@" --stdin < "$s/range"; }
names > "$s/file" || exit 6
names --text -G"$ph" > "$s/placeholder" || exit 6
names --text -G"$rp" > "$s/replaced" || exit 6
: > "$s/patch"
[ "$(cat "$s/commits")" = 0 ] || g log -p --diff-merges=first-parent --no-color --no-ext-diff --no-textconv --no-renames --format= -U0 --stdin < "$s/range" > "$s/patch" || exit 6
for f in commits file placeholder replaced patch refs snapshot pack; do
  printf '%s %s\000' "$f" "$(wc -c < "$s/$f" | tr -d ' ')" && cat "$s/$f" || exit 6
done
ok=1
`

// GitReviewScript is the review a relay of the agent's own user runs as
// the agent: it makes the review pack ($snap, printed as the "snapshot"
// frame), a bare git directory whose pack holds every object reachable
// from the approved commit, read through gitCheckoutView. The later push
// copies only the named pack into a fresh repository. Arguments: OBJECTS
// URL COMMIT PLACEHOLDER REPLACED.
const GitReviewScript = GitPrelude + `objs=$1 url=$2 c=$3 ph=$4 rp=$5
` + gitRefuseAlternates + `s=$(mktemp -d) && snap=$(mktemp -d) || exit 6
ok=0
trap 'rm -rf "$s"; [ "$ok" = 1 ] || rm -rf "$snap"' EXIT
` + gitCheckoutView + `g ls-remote "$url" > "$s/refs" || exit 11
# Pack the full closure of the reviewed commit. The later push must not
# borrow parent objects from the agent's writable checkout or its alternates.
pack=$(printf '%s\n' "$c" | g pack-objects --revs -q "$snap/g/objects/pack/pack") || exit 13
printf '%s' "$pack" > "$s/pack"
printf '%s' "$snap" > "$s/snapshot"
` + gitReviewTail

// GitPushScript pushes $3 to refs/heads/$4 from a fresh bare repository
// containing only the review's named pack ($1, $8). $6 is the commit this
// computer pushed to that branch before ("" for none): a branch origin has
// is refused unless it is at that commit. $7 is the branch as the review
// saw it ("" for none): the push is refused when origin's branch is not
// there now (exit 10), and it carries a lease on that state, so a writer
// that moves the branch during the push makes git or the server refuse it.
const GitPushScript = GitPrelude + `snap=$1 url=$2 c=$3 b=$4 label=$5 prev=$6 seen=$7
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

// GitDiscardScript removes the review's copy of a relay of the agent's own
// user when nothing more is pushed.
const GitDiscardScript = `rm -rf -- "$1"`
