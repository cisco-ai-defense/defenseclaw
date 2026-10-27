// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// GAP-2122: find -exec/-execdir/-ok with rm, unlink, rmdir or shred given
// only the found entry removes it, like -delete, and mv {} DEST moves it
// away; the same order rule applies, so a named log cleanup and a
// read-only -exec stay allowed. Only an exact embedded command (the
// program given only options and {}) is read; any other embedded command
// keeps the find partial, as before.
func TestR105GAP2122FindExecDeleteOfActiveState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		// GAP-2122
		{"exec rm hooks plus", "find ~/.defenseclaw/hooks -exec rm -f {} +", true, ""},
		{"exec rm root before name", `find ~/.defenseclaw -exec rm -f {} \; -name '*.log'`, true, ""},
		{"exec true or delete", `find ~/.defenseclaw -name '*.log' -exec true \; -o -delete`, true, ""},
		{"execdir rm installer", "find ~/.defenseclaw/installer -type f -execdir rm {} +", true, ""},
		{"exec unlink HOME hooks", `find $HOME/.defenseclaw/hooks -exec unlink {} \;`, true, ""},
		{"exec rm name config", `find ~/.defenseclaw -name config.yaml -exec rm {} \;`, true, ""},
		{"exec bin rm policies", "find ~/.defenseclaw/policies -type f -exec /bin/rm -f {} +", true, ""},
		{"exec mv policies out", `find ~/.defenseclaw/policies -exec mv {} /tmp/ \;`, true, ""},
		{"ok rm previous", `find ~/.defenseclaw/previous -ok rm {} \;`, true, ""},
		// pod check7: any program that may change what it is handed.
		{"exec sh c rm hooks", `find ~/.defenseclaw/hooks -exec sh -c 'rm -f "$1"' _ {} \;`, true, ""},
		{"exec truncate hooks", "find ~/.defenseclaw/hooks -type f -exec truncate -s 0 {} +", true, ""},
		{"exec cp devnull hooks", `find ~/.defenseclaw/hooks -type f -exec cp /dev/null {} \;`, true, ""},
		{"exec sudo rm hooks", "find ~/.defenseclaw/hooks -exec sudo rm -f {} +", true, ""},
		{"exec env rm hooks", "find ~/.defenseclaw/hooks -exec env rm -f {} +", true, ""},
		{"exec sed root", "find ~/.defenseclaw -type f -exec sed -i s/a/b/ {} +", true, ""},
		{"exec tee config", `find ~/.defenseclaw/config.yaml -exec tee {} \;`, true, ""},
		{"xargs rm hooks", "find ~/.defenseclaw/hooks -type f | xargs rm -f", true, ""},
		{"xargs 0 rm root", "find ~/.defenseclaw -type f -print0 | xargs -0 rm -f", true, ""},
		{"xargs n truncate installer", "find $HOME/.defenseclaw/installer -type f | xargs -n 1 truncate -s 0", true, ""},
		// Benign: named cleanup through -exec, read-only -exec, other trees.
		{"exec rm log cleanup", `find ~/.defenseclaw -name '*.log' -exec rm -f {} \;`, false, ""},
		{"exec rm log cleanup plus", "find ~/.defenseclaw -name '*.log' -mtime +7 -exec rm -f {} +", false, ""},
		{"exec ls root", `find ~/.defenseclaw -type f -exec ls -l {} \;`, false, ""},
		{"exec grep root", "find ~/.defenseclaw -exec grep -l fixture {} +", false, ""},
		{"exec sha256sum hooks", "find ~/.defenseclaw/hooks -type f -exec sha256sum {} +", false, ""},
		{"exec rm logs tree", "find ~/.defenseclaw/logs -exec rm -f {} +", false, ""},
		{"exec rm project objects", "find ./build -name '*.o' -exec rm -f {} +", false, ""},
		{"exec gzip log cleanup", "find ~/.defenseclaw -name '*.log' -exec gzip {} +", false, ""},
		{"exec cat root", "find ~/.defenseclaw -type f -exec cat {} +", false, ""},
		{"exec chmod project scripts", "find . -name '*.sh' -exec chmod +x {} +", false, ""},
		{"exec gofmt project", "find . -name '*.go' -exec gofmt -w {} +", false, ""},
		{"exec sh c wc project", `find . -type f -exec sh -c 'wc -l "$1"' _ {} \;`, false, ""},
		{"xargs rm log cleanup", "find ~/.defenseclaw -name '*.log' -print0 | xargs -0 rm -f", false, ""},
		{"xargs sha256sum hooks", "find ~/.defenseclaw/hooks -type f | xargs sha256sum", false, ""},
		{"xargs grep root", "find ~/.defenseclaw -type f | xargs grep -l fixture", false, ""},
		{"xargs rm project pyc", "find . -name '*.pyc' | xargs rm -f", false, ""},
		// pod check8: residual forms, a wrapped xargs and pass-through
		// stages between find and xargs.
		{"sudo xargs rm hooks", "find ~/.defenseclaw/hooks -type f | sudo xargs rm -f", true, ""},
		{"tee devnull xargs rm hooks", "find ~/.defenseclaw/hooks -type f | tee /dev/null | xargs rm", true, ""},
		{"tee log xargs rm hooks", "find ~/.defenseclaw/hooks -type f | tee /tmp/l | xargs rm", true, ""},
		{"grep xargs rm hooks", "find ~/.defenseclaw/hooks -type f | grep -v zz | xargs rm -f", true, ""},
		{"xargs cp into hooks", "find ~/.defenseclaw/policies -type f | xargs cp -t ~/.defenseclaw/hooks", true, ""},
		// pod check8: writers that stay writers.
		{"exec sort o config", `find ~/.defenseclaw/config.yaml -exec sort -o {} {} \;`, true, ""},
		{"exec dd of hooks", `find ~/.defenseclaw/hooks -type f -exec dd if=/dev/null of={} \;`, true, ""},
		{"exec perl pi hooks", "find ~/.defenseclaw/hooks -type f -exec perl -pi -e s/a/b/ {} +", true, ""},
		{"exec sed w root", `find ~/.defenseclaw -type f -exec sed -n 'w /tmp/x' {} \;`, true, ""},
		{"exec awk print to file", `find ~/.defenseclaw/hooks -type f -exec awk '{print > FILENAME}' {} \;`, true, ""},
		{"exec awk system", `find ~/.defenseclaw/hooks -type f -exec awk 'BEGIN{system("rm -f " ARGV[1])}' {} \;`, true, ""},
		{"exec cp into hooks", `find ~/.defenseclaw/policies -type f -exec cp {} ~/.defenseclaw/hooks/ \;`, true, ""},
		{"execdir cp beside", `find ~/.defenseclaw/hooks -type f -execdir cp {} backup \;`, true, ""},
		{"exec tar extract hooks", `find ~/.defenseclaw/hooks -name '*.tar' -execdir tar -xf {} \;`, true, ""},
		{"exec zip move hooks", "find ~/.defenseclaw/hooks -type f -exec zip -m /tmp/h.zip {} +", true, ""},
		{"exec json tool onto itself", `find ~/.defenseclaw -name '*.json' -exec python3 -m json.tool {} {} \;`, true, ""},
		// pod check8 P2 regression: reads and copies out of state stay
		// allowed through find -exec and xargs.
		{"exec awk end root", `find ~/.defenseclaw -type f -exec awk 'END{print FILENAME, NR}' {} +`, false, ""},
		{"exec sort root", "find ~/.defenseclaw -type f -exec sort {} +", false, ""},
		{"exec jq root", `find ~/.defenseclaw -type f -exec jq . {} \;`, false, ""},
		{"exec jq json", `find ~/.defenseclaw -name '*.json' -exec jq . {} \;`, false, ""},
		{"exec sed n 1p", `find ~/.defenseclaw -name '*.json' -exec sed -n 1p {} \;`, false, ""},
		{"exec json tool", `find ~/.defenseclaw -name '*.json' -exec python3 -m json.tool {} \;`, false, ""},
		{"exec cp out tmp", `find ~/.defenseclaw -type f -exec cp {} /tmp/dc-backup/ \;`, false, ""},
		{"exec cp policies to project", `find ~/.defenseclaw/policies -type f -exec cp {} ~/proj/policies-copy/ \;`, false, ""},
		{"exec cp config out", `find ~/.defenseclaw/config.yaml -exec cp {} /tmp/cfg.bak \;`, false, ""},
		{"exec cut root", "find ~/.defenseclaw -type f -exec cut -c1-20 {} +", false, ""},
		{"exec tar create out", "find ~/.defenseclaw/policies -type f -exec tar -cf /tmp/policies.tar {} +", false, ""},
		{"xargs cp t out", "find ~/.defenseclaw -type f -print0 | xargs -0 cp -t /tmp/dc-backup", false, ""},
		{"xargs jq root", "find ~/.defenseclaw -name '*.json' | xargs jq .", false, ""},
		{"tee xargs sha256sum", "find ~/.defenseclaw/hooks -type f | tee /tmp/l | xargs sha256sum", false, ""},
		{"sudo xargs ls hooks", "find ~/.defenseclaw/hooks -type f | sudo xargs ls -l", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
