// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

// GAP-0314 (TRIAGE105 T01, Ubuntu 24.04 arm64, Claude Code action mode): a
// python handle write (Path.home()/'.ssh'/'authorized_keys').open('a').write,
// and node/perl one-liners that append to ~/.ssh/authorized_keys were
// allowed by the registered hook while the write_text/write_bytes forms
// blocked; a real Claude Code TUI appended to the file. Every interpreter
// writer that names the key path is a protected target in action mode.
func TestActionInterpreterHandleWriteToKeyIsProtected(t *testing.T) {
	skipPOSIXGrammarOnWindows(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, command := range []string{
		`python3 -c "from pathlib import Path; Path.home().joinpath('.ssh','authorized_keys').open('a').write('r105-marker\n')"`,
		`python3 -c "import os; open(os.path.expanduser('~/.ssh/authorized_keys'),'a').write('r105-marker\n')"`,
		`python3 -c "import os; open(os.path.join(os.environ['HOME'],'.ssh','authorized_keys'),'a').write('r105-marker\n')"`,
		`python3 -c "import pathlib; pathlib.Path('~/.ssh/authorized_keys').expanduser().write_text('r105-marker')"`,
		`python3 -c "import pathlib; p=pathlib.Path.home()/'.ssh'/'authorized_keys'; p.open('a').write('r105-marker\n')"`,
		`node -e "require('fs').appendFileSync(require('os').homedir()+'/.ssh/authorized_keys','r105-marker')"`,
		`perl -e 'open(F,">>$ENV{HOME}/.ssh/authorized_keys"); print F "r105-marker"'`,
		`python3 -c "from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; p.write_text(p.read_text() + 'r105-marker\n')"`,
		`python3 -c "from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; f = p.open('a'); f.write('r105-marker\n')"`,
		`python3 -c "from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; p.write_bytes(b'r105-marker')"`,
		`python3 -c "from pathlib import Path; (Path.home() / '.ssh' / 'authorized_keys').open('a').write('r105-marker\n')"`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("ActionCommandDecision(%q) = %q, want protected-target", command, got)
		}
	}
	for _, command := range []string{
		`echo r105-benign-ok`,
		`python3 -c "from pathlib import Path; print(Path.home().joinpath('.ssh','authorized_keys').exists())"`,
		`python3 -c "from pathlib import Path; Path('notes.txt').open('a').write('x')"`,
		`node -e "require('fs').appendFileSync('notes.txt','x')"`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("ActionCommandDecision(%q) = %q, want allow", command, got)
		}
	}
}
