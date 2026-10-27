// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2267: a find with no starting point searches '.', and a start that
// contains the state root (~, $HOME) reaches the state tree as a start at
// the root does; named cleanups and -maxdepth limits above the root's
// entries stay allowed.
func TestFindAncestorOrDefaultStartOfActiveState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, cwd := r105StateFixture(t)
	rule := filepath.Join(home, ".defenseclaw", "policies", "guardrail", "zz-rule-one.yaml")
	if err := os.MkdirAll(filepath.Dir(rule), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule, []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []r105StateRow{
		{"cd root find delete", "cd ~/.defenseclaw && find -delete", true, ""},
		{"cd root find follow delete", "cd ~/.defenseclaw && find -follow -delete", true, ""},
		{"cd root find false or delete", "cd ~/.defenseclaw && find -false -o -delete", true, ""},
		{"cd hooks find exec rm", `cd ~/.defenseclaw/hooks && find -type f -exec rm {} \;`, true, ""},
		{"home type f delete", "find ~ -type f -delete", true, ""},
		{"home exec rm", `find ~ -type f -exec rm {} \;`, true, ""},
		{"home exec sh c rm rf", `find ~ -exec sh -c 'rm -rf "$1"' _ {} \;`, true, ""},
		{"home exec sh c rm", `find ~ -type f -exec sh -c 'rm "$1"' _ {} \;`, true, ""},
		{"home slash mtime delete", "find ~/ -mtime +30 -delete", true, ""},
		{"home name hooks delete", "find ~ -name hooks -exec rm -rf {} +", true, ""},
		{"home name config delete", "find ~ -name config.yaml -delete", true, ""},
		{"home yaml delete", "find ~ -name '*.yaml' -delete", true, ""},
		{"home sh exec rm", "find ~ -iname '*.SH' -exec rm -f {} +", true, ""},
		// A name only the real state tree has (a rule file).
		{"home real policy name", "find ~ -name 'zz-rule*' -delete", true, ""},
		{"home path previous delete", "find ~ -path '*/previous/*' -type f -delete", true, ""},
		{"home xargs rm", "find ~ -type f | xargs rm -f", true, ""},
		{"home maxdepth 2 delete", "find ~ -maxdepth 2 -type f -delete", true, ""},
		{"home maxdepth 1 exec rm rf", "find ~ -maxdepth 1 -exec rm -rf {} +", true, ""},
		// Benign twins.
		{"home DS_Store", "find ~ -name '.DS_Store' -exec rm {} +", false, ""},
		{"home maxdepth 1 tmp xargs", "find ~ -maxdepth 1 -name '*.tmp' | xargs rm -f", false, ""},
		{"home log sh c", `find ~ -name '*.log' -exec sh -c 'rm "$1"' _ {} \;`, false, ""},
		{"home tmp delete", "find ~ -name '*.tmp' -delete", false, ""},
		{"home py compile", "find ~ -maxdepth 3 -type f -name '*.py' -exec python3 -m py_compile {} +", false, ""},
		{"home maxdepth 1 type f rm", "find ~ -maxdepth 1 -type f -exec rm -f {} +", false, ""},
		{"home py grep", "find ~ -type f -name '*.py' | xargs grep -l fixture", false, ""},
		{"home type f ls", "find ~ -type f -exec ls -l {} +", false, ""},
		{"no start pyc", "find -name '*.pyc' -delete", false, ""},
		{"no start project files", "find -type f -name '*.o' -exec rm -f {} +", false, ""},
		{"dot project delete", "find . -type d -empty -delete", false, ""},
		{"no start list", "find -type f", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
