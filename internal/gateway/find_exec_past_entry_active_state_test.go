// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
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
	_, cwd := r105StateFixture(t)
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
		{"project execdir rm parent", `find ./build -name '*.o' -execdir rm -f ../stale.txt \;`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
