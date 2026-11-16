// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
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
		// GAP-2267 $HOME starts (pod check14 H1-H4, H13).
		{"HOME type f delete", "find $HOME -type f -delete", true, ""},
		{"braced HOME type f delete", "find ${HOME} -type f -delete", true, ""},
		{"quoted HOME type f delete", `find "$HOME" -type f -delete`, true, ""},
		{"HOME slash exec rm plus", "find $HOME/ -type f -exec rm {} +", true, ""},
		{"quoted HOME then slash exec rm", `find "$HOME"/ -type f -exec rm {} +`, true, ""},
		{"quoted HOME slash inside delete", `find "$HOME/" -mtime +30 -delete`, true, ""},
		{"quoted braced HOME exec rm", `find "${HOME}" -type f -exec rm {} \;`, true, ""},
		// Benign $HOME twins.
		{"HOME DS_Store", "find $HOME -name '.DS_Store' -exec rm {} +", false, ""},
		{"quoted HOME tmp delete", `find "$HOME" -name '*.tmp' -delete`, false, ""},
		{"HOME type f ls", "find ${HOME} -type f -exec ls -l {} +", false, ""},
		{"ls HOME", "ls -la $HOME", false, ""},
		{"du quoted HOME", `du -sh "$HOME"`, false, ""},
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

// GAP-2267 pod check9: an upgraded account keeps a whole Python venv under
// previous/ (about 25000 entries, thousands of *.pyc). A find from ~ whose
// name test matches no protected name, and a bytecode cleanup, stay
// allowed there; a name the saved venv does hold still blocks.
func TestFindAncestorStartOfUpgradedAccountState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, cwd := r105StateFixture(t)
	venv := filepath.Join(home, ".defenseclaw", "previous", "venv", "lib", "python3.12", "site-packages")
	for i := 0; i < 21000; i++ {
		dir := filepath.Join(venv, fmt.Sprintf("pkg%03d", i/100))
		name := fmt.Sprintf("m%05d.py", i)
		if i%3 == 0 {
			dir = filepath.Join(dir, "__pycache__")
			name = fmt.Sprintf("m%05d.cpython-312.pyc", i)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"home node_modules prune rm", "find ~ -name node_modules -type d -prune -exec rm -rf {} +", false, ""},
		{"home orig delete", "find ~ -name '*.orig' -delete", false, ""},
		{"home class delete", "find ~ -name '*.class' -delete", false, ""},
		{"home pyc delete", "find ~ -name '*.pyc' -delete", false, ""},
		{"cd home dot o delete", "cd ~ && find . -name '*.o' -delete", false, ""},
		{"home target prune rm", "find ~ -type d -name target -prune -exec rm -rf {} +", false, ""},
		{"home core delete", "find ~ -name 'core.[0-9]*' -delete", false, ""},
		{"home rej xargs rm", "find ~ -name '*.rej' | xargs rm -f", false, ""},
		{"cd home dot pyc delete", "cd ~ && find . -name '*.pyc' -delete", false, ""},
		{"cd home pycache rm", "cd ~ && find . -name __pycache__ -type d -exec rm -rf {} +", false, ""},
		{"home pycache prune rm", "find ~ -name '__pycache__' -prune -exec rm -rf {} +", false, ""},
		{"home tmp delete", "find ~ -name '*.tmp' -delete", false, ""},
		// Still blocked: names the state holds, and no name test at all.
		{"home py delete", "find ~ -name '*.py' -delete", true, ""},
		{"home config delete", "find ~ -name config.yaml -delete", true, ""},
		{"home install sh delete", "find ~ -name 'install.sh' -exec rm -f {} +", true, ""},
		{"home type f delete", "find ~ -type f -delete", true, ""},
		{"home path previous delete", "find ~ -path '*/previous/*' -type f -delete", true, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
