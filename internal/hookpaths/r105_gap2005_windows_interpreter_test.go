// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-2005 RV8-2: the interpreter key-path class rule (both names plus an
// executable writer) ran only in the POSIX grammar, so on a Windows home a
// PowerShell python -c or node -e write to the authorized-keys file was
// allowed. The Windows readings apply the same rule.
func TestActionWindowsInterpreterBuiltKeyPathIsProtected(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Windows readings run on a Windows home on a Windows host")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{proj, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	msys := filepath.ToSlash(home)
	if volume := filepath.VolumeName(home); len(volume) == 2 && volume[1] == ':' {
		msys = "/" + strings.ToLower(volume[:1]) + filepath.ToSlash(home[2:])
	}
	for _, command := range []string{
		`python -c "h=r'` + home + `'; open('{}\\.ssh\\{}'.format(h,'authorized_keys'),'a').write('x')"`,
		`python -c "import os; h=os.environ['USERPROFILE']; open('%s/.ssh/%s' % (h,'authorized_keys'),'a').write('x')"`,
		`python -c "import os; h=r'` + home + `'; d=os.path.join(h, '.ssh'); open(os.path.join(d, 'authorized_keys'),'a').write('x')"`,
		`python -c "from pathlib import Path; Path.home(); h=r'` + home + `'; open(f'{h}/.ssh/authorized_keys','a').write('x')"`,
		`python -c "from pathlib import Path; (Path.home()/'.ssh'/'authorized_keys').open('a').write('x')"`,
		`py -3 -c "from pathlib import Path; (Path.home()/'.ssh'/'authorized_keys').open('a').write('x')"`,
		`& 'C:\Program Files\Python313\python.exe' -c "import os; open(os.path.join(os.environ['USERPROFILE'],'.ssh','authorized_keys'),'a').write('x')"`,
		`node -e "require('fs').appendFileSync(require('path').join(require('os').homedir(),'.ssh','authorized_keys'),'x')"`,
		`ruby -e "File.open(File.join(Dir.home, '.ssh', 'authorized_keys'), 'a') { |f| f.write('x') }"`,
		"& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc @'\npython3 -c 'h=\"" + msys + "\"; open(\"{}/.ssh/{}\".format(h, \"authorized_keys\"),\"a\").write(\"x\")'\n'@",
	} {
		if got := ActionCommandDecision(command, proj, home); got != "protected-target" {
			t.Errorf("ActionCommandDecision(%q) = %q, want protected-target", command, got)
		}
	}
	for _, command := range []string{
		`python -c "open('notes.txt','a').write('x')"`,
		`python -c "import os; print(os.path.join('a', '.ssh_backup', 'keys'))"`,
		`python -c "print('see .ssh/authorized_keys')"`,
		`node -e "require('fs').writeFileSync('out.txt','x')"`,
		`python -m pytest -q`,
	} {
		if got := ActionCommandDecision(command, proj, home); got != "" {
			t.Errorf("ActionCommandDecision(%q) = %q, want allow", command, got)
		}
	}
}
