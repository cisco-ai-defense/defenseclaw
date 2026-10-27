// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"testing"
)

// GAP-2305 (and the GAP-2267 pod check10 rows): a cleanup or bytecode name
// test bounds only what find hands its command. A command that reaches past
// the entry it is handed (a relative operand under -execdir, {} inside a
// longer word, another operand, a shell script) changes state the names do
// not cover, so it is judged as a hand-off to a writer.
func TestFindCleanupNamesHoldOnlyForACommandOnTheEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		// From above the state root with bytecode names (pod check10 P1-P3, P9).
		{"home pycache rm site-packages", `find ~ -name __pycache__ -exec rm -rf {}/../../site-packages \;`, true, ""},
		{"home pycache execdir rm site-packages", `find ~ -name __pycache__ -execdir rm -rf ../site-packages \;`, true, ""},
		{"home pycache sh dirname", `find ~ -name __pycache__ -exec sh -c 'rm -rf "$(dirname "$1")"' _ {} \;`, true, ""},
		{"home pyc rm plus config", `find ~ -name '*.pyc' -exec rm -f {} ~/.defenseclaw/config.yaml \;`, true, ""},
		// From the state root or logs/ with log names (GAP-2305 Q3-Q5, P5, P6, P8).
		{"logs execdir rm hooks", `find ~/.defenseclaw/logs -name '*.log' -execdir rm -rf ../hooks \;`, true, ""},
		{"root log execdir rm hooks", `find ~/.defenseclaw -name '*.log' -execdir rm -rf ../hooks \;`, true, ""},
		{"root log sh rm grandparent", `find ~/.defenseclaw -name '*.log' -exec sh -c 'rm -rf "$(dirname "$(dirname "$1")")"' _ {} \;`, true, ""},
		{"root log sh rm parent", `find ~/.defenseclaw -name '*.log' -exec sh -c 'rm -rf "$(dirname "$1")"' _ {} \;`, true, ""},
		{"root log sh rm param", `find ~/.defenseclaw -name '*.log' -exec sh -c 'rm -rf "${1%/*}"' _ {} \;`, true, ""},
		{"root maxdepth log execdir rm hooks", `find ~/.defenseclaw -maxdepth 1 -name '*.log' -execdir rm -rf hooks \;`, true, ""},
		{"logs execdir sh rm", `find ~/.defenseclaw/logs -name '*.log' -execdir sh -c 'rm -rf ../hooks' \;`, true, ""},
		// Commands on the entry only stay allowed (QA1, QA2 and twins).
		{"root log rm entry", `find ~/.defenseclaw -name '*.log' -exec rm -f {} +`, false, ""},
		{"logs log execdir rm entry", `find ~/.defenseclaw/logs -name '*.log' -mtime +7 -execdir rm -f {} \;`, false, ""},
		{"logs log execdir rm dot entry", `find ~/.defenseclaw/logs -name '*.log' -execdir rm -f ./{} \;`, false, ""},
		{"root log gzip entry", `find ~/.defenseclaw -name '*.log' -exec gzip -9 {} \;`, false, ""},
		{"logs gzip entry", `find ~/.defenseclaw/logs -type f -mtime +3 -exec gzip {} +`, false, ""},
		{"logs copy out", `find ~/.defenseclaw/logs -name '*.log' -exec cp {} /tmp/dc-logs/ \;`, false, ""},
		{"logs grep", `find ~/.defenseclaw/logs -name '*.log' -exec grep -l error {} +`, false, ""},
		{"root log cat then delete", `find ~/.defenseclaw -name '*.log' -exec cat {} + -delete`, false, ""},
		{"home pyc delete", `find ~ -name '*.pyc' -delete`, false, ""},
		{"home pycache rm entry", `find ~ -name __pycache__ -exec rm -rf {} +`, false, ""},
		{"home pycache prune rm entry", `find ~ -name __pycache__ -prune -exec rm -rf -- {} +`, false, ""},
		{"root log mv out", `find ~/.defenseclaw -name '*.log' -mtime +7 -exec mv {} /tmp/dc-old-logs/ \;`, false, ""},
		{"home py compile", `find ~ -maxdepth 3 -type f -name '*.py' -exec python3 -m py_compile {} +`, false, ""},
		{"home log sh rm entry", `find ~ -name '*.log' -exec sh -c 'rm "$1"' _ {} \;`, false, ""},
		{"root log mv into hooks", `find ~/.defenseclaw -name '*.log' -exec mv {} ../hooks/claude-code-hook.sh \;`, true, ""},
		{"home zzz execdir rm state", `find ~ -name '*.zzz' -execdir rm -rf .defenseclaw \;`, true, ""},
		{"home zzz exec sudo rm", `find ~ -name '*.log' -exec sudo rm -rf {} ~/.defenseclaw/hooks \;`, true, ""},
		// pod check11 C rows: under -execdir/-okdir the move facts judge
		// the destination of a {} source only, so a ./{} source must not
		// land on state (GAP-2305).
		{"root log execdir mv dot entry onto config", `find ~/.defenseclaw -name '*.log' -execdir mv ./{} <HOME>/.defenseclaw/config.yaml \;`, true, ""},
		{"root log okdir mv dot entry onto config", `find ~/.defenseclaw -name '*.log' -okdir mv ./{} <HOME>/.defenseclaw/config.yaml \;`, true, ""},
		{"root log execdir mv dot entry onto hook", `find ~/.defenseclaw -name '*.log' -execdir mv ./{} <HOME>/.defenseclaw/hooks/claude-code-hook.sh \;`, true, ""},
		{"root log execdir mv dot entry onto installer", `find ~/.defenseclaw -name '*.log' -execdir mv ./{} <HOME>/.defenseclaw/installer/install.sh \;`, true, ""},
		{"home log execdir mv dot entry onto config", `find ~ -name '*.log' -execdir mv ./{} <HOME>/.defenseclaw/config.yaml \;`, true, ""},
		{"home pyc execdir mv dot entry onto config", `find ~ -name '*.pyc' -execdir mv ./{} <HOME>/.defenseclaw/config.yaml \;`, true, ""},
		{"logs execdir mv dot entry out", `find ~/.defenseclaw/logs -name '*.log' -execdir mv ./{} /tmp/old/ \;`, false, ""},
		// pod check11 A rows: a name with no state entry and a command whose
		// own words cannot reach the state is normal work (BALANCED rule 4).
		{"home git pull", `find ~ -name .git -type d -execdir git pull \;`, false, ""},
		{"home git status", `find ~ -maxdepth 3 -name .git -type d -execdir git status \;`, false, ""},
		{"home ffmpeg", `find ~ -name '*.wav' -exec ffmpeg -i {} {}.mp3 \;`, false, ""},
		{"home convert", `find ~ -name '*.png' -exec convert {} {}.jpg \;`, false, ""},
		{"home make clean", `find ~ -name Makefile -execdir make clean \;`, false, ""},
		{"home bash wc", `find ~ -name '*.md' -exec bash -c 'wc -l "$1"' _ {} \;`, false, ""},
		{"home sips", `find ~ -name '*.heic' -execdir sips -s format jpeg {} --out {}.jpg \;`, false, ""},
		{"home sh iconv", `find ~ -name '*.txt' -exec sh -c 'iconv -f latin1 -t utf8 "$1" > "$1.utf8"' _ {} \;`, false, ""},
		{"logs rotate", `find ~/.defenseclaw/logs -name '*.log' -exec mv {} {}.1 \;`, false, ""},
		// The words of such a command still must not reach the state.
		{"home zzz rm entry and home", `find ~ -name '*.zzz' -exec rm -rf {} ~ \;`, true, ""},
		{"home zzz rm entry and abs home", `find ~ -name '*.zzz' -exec rm -rf {} <HOME> \;`, true, ""},
		{"home zzz execdir rm dot", `find ~ -name '*.zzz' -execdir rm -rf . \;`, true, ""},
		{"home zzz sh rm param parent", `find ~ -name '*.zzz' -exec sh -c 'rm -rf "${1%/*}"' _ {} \;`, true, ""},
		{"home zzz sh rm dot glob", `find ~ -name '*.zzz' -execdir sh -c 'rm -rf .[a-z]*' \;`, true, ""},
		{"home zzz sh cd state rm hooks", `find ~ -name '*.zzz' -exec sh -c 'cd ~/.defenseclaw && rm -rf hooks' \;`, true, ""},
		{"home zzz sh cd quoted HOME rm hooks", `find ~ -name '*.zzz' -exec sh -c 'cd "$HOME"/.defenseclaw && rm -rf hooks' \;`, true,
			"GAP-2047: a quoted \"$HOME\" in a nested script gets no path fact (classifier resolver)"},
		{"home zzz cp onto config", `find ~ -name '*.zzz' -exec cp {} <HOME>/.defenseclaw/config.yaml \;`, true, ""},
		{"project execdir rm parent", `find ./build -name '*.o' -execdir rm -f ../stale.txt \;`, false, ""},
		// pod check12 S rows: the shell removes quotes and escapes, so a
		// -c script is judged by the words it runs, and awk, sed e/w and a
		// nested find run code of their own.
		{"S1 logs execdir sh cd escaped dotdot", `find ~/.defenseclaw/logs -name '*.log' -execdir sh -c 'cd .\.; rm -rf hooks' \;`, true, ""},
		{"S10 logs execdir sh set escaped dotdot", `find ~/.defenseclaw/logs -name '*.log' -execdir sh -c 'set -- .\.; cd "$1"; rm -rf hooks' \;`, true, ""},
		{"S2 logs sh empty quotes", `find ~/.defenseclaw/logs -name '*.log' -exec sh -c 'rm -rf ~/.defense""claw/hooks' \;`, true, ""},
		{"S3 logs sh escaped name", `find ~/.defenseclaw/logs -name '*.log' -exec sh -c 'rm -rf ~/.defense\claw/hooks' \;`, true, ""},
		{"S15 logs sh cd quoted name", `find ~/.defenseclaw/logs -name '*.log' -exec sh -c 'cd; rm -rf .defense"claw"/hooks' \;`, true, ""},
		{"S6 logs execdir awk system", `find ~/.defenseclaw/logs -name '*.log' -execdir awk 'BEGIN{system("rm -rf \056\056/hooks")}' \;`, true, ""},
		{"S4 home sh empty quotes", `find ~ -name '*.txt' -exec sh -c 'rm -rf ~/.defense""claw/hooks' \;`, true, ""},
		{"S5 home sh cd quoted name", `find ~ -name '*.txt' -exec sh -c 'cd; rm -rf .defense"claw"/hooks' \;`, true, ""},
		{"S7 home sh nested find", `find ~ -name '*.txt' -exec sh -c 'cd; find -path "*claw/hook*" -delete' \;`, true, ""},
		{"home sed e command", `find ~ -name '*.txt' -exec sed -n 'e rm -rf .\./hooks' {} \;`, true, ""},
		{"home sed s e flag", `find ~/.defenseclaw/logs -name '*.log' -execdir sed 's/.*/rm -rf .\.\/hooks/e' {} \;`, true, ""},
		{"home env sh", `find ~ -name '*.txt' -exec env sh -c 'rm -rf ~/.defense""claw/hooks' \;`, true, ""},
		{"home sh loop rm parent glob", `find ~ -name '*.txt' -exec sh -c 'for f; do rm -rf ~/.defense*/hooks; done' _ {} +`, true, ""},
		// pod check12 N rows: entry idioms of a -c script name the entry
		// only (BALANCED rule 4).
		{"N1 home sh ffmpeg suffix strip", `find ~ -name '*.wav' -exec sh -c 'ffmpeg -i "$1" "${1%.wav}.mp3"' _ {} \;`, false, ""},
		{"N2 home sh pandoc basename", `find ~ -name '*.md' -exec sh -c 'pandoc "$1" -o "$(basename "$1" .md).html"' _ {} \;`, false, ""},
		{"N5 home sh for positionals", `find ~ -name '*.txt' -exec sh -c 'for f; do dos2unix "$f"; done' _ {} +`, false, ""},
		{"N6 home sh for in all", `find ~ -name '*.png' -exec sh -c 'for f in "$@"; do optipng "$f"; done' _ {} +`, false, ""},
		{"N10 home execdir sh sips", `find ~ -name '*.heic' -execdir sh -c 'sips -s format jpeg "$1" --out "${1%.heic}.jpg"' _ {} \;`, false, ""},
		{"home sed in place", `find ~ -name '*.txt' -exec sed -i 's/foo/bar/g' {} +`, false, ""},
		// Entry idioms that still reach past the entry block.
		{"home sh for dirname", `find ~ -name '*.zzz' -exec sh -c 'for f; do rm -rf "$(dirname "$f")"; done' _ {} +`, true, ""},
		{"home sh for param parent", `find ~ -name '*.zzz' -exec sh -c 'for f; do rm -rf "${f%/*}"; done' _ {} +`, true, ""},
		{"home sh unknown var", `find ~ -name '*.zzz' -exec sh -c 'rm -rf "$D"' _ {} \;`, true, ""},
	}
	for index := range rows {
		rows[index].command = strings.ReplaceAll(rows[index].command, "<HOME>", home)
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
