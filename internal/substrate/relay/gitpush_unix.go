// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package relay

// The scripts only a separated relay runs (runGitOp, gitop_unix.go); a
// relay elsewhere is never separated (gitop_other.go).

// gitPackScript runs as the agent's user on a separated relay: it writes
// to stdout one pack of the commit on the first line of stdin and of the
// commits and tags, of the ids on the other lines, that the checkout
// holds (origin's refs, so the review can tell what origin has). Whatever
// it writes, the relay keeps only objects whose content matches their id.
// Argument: OBJECTS.
const gitPackScript = GitPrelude + `objs=$1
` + gitRefuseAlternates + `snap=$(mktemp -d) || exit 6
trap 'rm -rf "$snap"' EXIT
` + gitCheckoutView + `IFS= read -r c || exit 6
{ printf '%s\n' "$c"; g cat-file --batch-check='%(objectname) %(objecttype)' | awk '$2 == "commit" || $2 == "tag" { print $1 }'; } > "$snap/revs" || exit 6
g pack-objects --revs --stdout -q < "$snap/revs" || exit 13
`

// gitRelayInitScript makes the relay's review repository $R/g and reads
// origin's refs into $R/refs, as the relay's user. Arguments: DIR URL.
const gitRelayInitScript = GitPrelude + `R=$1 url=$2
git init -q --bare --template= "$R/g" || exit 6
export GIT_DIR=$R/g
g ls-remote "$url" > "$R/refs" || exit 11
`

// gitRelayIndexScript reads a pack on stdin into $R/g: index-pack computes
// every object id from its content (--strict also checks each object), so
// the repository holds only hash-true objects. Argument: DIR.
const gitRelayIndexScript = GitPrelude + `export GIT_DIR=$1/g
g index-pack --stdin --strict >/dev/null || exit 14
`

// gitRelayReviewScript is the review of a separated relay, as its own user,
// of the relay's repository $R/g only (no alternates): the commit and every
// object it reaches must be there. Arguments: DIR URL COMMIT PLACEHOLDER
// REPLACED SNAPSHOT.
const gitRelayReviewScript = GitPrelude + `R=$1 url=$2 c=$3 ph=$4 rp=$5 tok=$6
export GIT_DIR=$R/g
[ "$(g cat-file -t "$c" 2>/dev/null)" = commit ] || { echo "the agent's checkout did not give commit $c" >&2; exit 14; }
g fsck --connectivity-only --no-reflogs --no-progress "$c" >/dev/null 2>&1 || { echo "the agent's checkout did not give every object of $c" >&2; exit 14; }
s=$R/s ok=0
rm -rf "$s" && mkdir "$s" || exit 6
cp "$R/refs" "$s/refs" || exit 6
set -- "$R"/g/objects/pack/pack-*.pack
[ "$#" = 1 ] && [ -f "$1" ] || { echo "no single review pack" >&2; exit 6; }
p=${1##*/pack-}
printf '%s' "${p%.pack}" > "$s/pack"
printf '%s' "$tok" > "$s/snapshot"
` + gitReviewTail + `rm -rf "$s"
`
