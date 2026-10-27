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
	}
	for index := range rows {
		rows[index].command = strings.ReplaceAll(rows[index].command, "<HOME>", home)
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
