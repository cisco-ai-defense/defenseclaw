// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestLinkMadeInTheCommandThenReplacedByAMoveIsAnOrdinaryWrite: a project
// link the command makes to a project file, then a plain mv onto that link
// (rename(2) replaces the link entry), and a pathlib hardlink_to or
// symlink_to of a project file followed by an append, write no protected
// file and are allowed per-user and managed, as the same move onto a link
// made earlier and the os.link forms are (rel-1-0-6:GAP-0195). A link made to
// the keys file, a write through its backup name, a moved disk link to the
// keys file and a link made after the move keep blocking.
func TestLinkMadeInTheCommandThenReplacedByAMoveIsAnOrdinaryWrite(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"ln -sfn after cd then mv onto it", "project", `cd {P} && ln -sfn README.md plink && mv a.txt plink`, "allow"},
		{"ln -s then mv onto it", "project", `ln -s README.md plink && mv a.txt plink`, "allow"},
		{"ln -sfn then mv -b onto it", "project", `cd {P} && ln -sfn README.md plink && mv -b a.txt plink`, "allow"},
		{"separate statements with --backup=simple", "project", `cd {P}; ln -sfn README.md plink; mv --backup=simple a.txt plink`, "allow"},
		{"ln -s, mv onto it, then append to it", "project", `ln -s README.md plink && mv a.txt plink && echo y >> plink`, "allow"},
		{"pathlib hardlink_to then append", "project", `python3 -c "import pathlib; pathlib.Path('kl6').hardlink_to('README.md'); open('kl6','a').write('k')"`, "allow"},
		{"from pathlib import Path hardlink_to then append", "project", `python3 -c "from pathlib import Path; Path('kl6').hardlink_to('README.md'); open('kl6','a').write('k')"`, "allow"},
		{"pathlib symlink_to then append", "project", `python3 -c "import pathlib; pathlib.Path('kl6').symlink_to('README.md'); open('kl6','a').write('k')"`, "allow"},
		{"link to the keys file then write", "project", `ln -sfn ../.ssh/authorized_keys plink && echo k >> plink`, "block"},
		{"link to the keys file, mv onto it, write", "project", `ln -sfn ../.ssh/authorized_keys plink && mv a.txt plink && echo k >> plink`, "block"},
		{"link to the keys file, mv -b, write the backup", "project", `ln -sfn ../.ssh/authorized_keys plink && mv -b a.txt plink && echo k >> plink~`, "block"},
		{"link to .ssh, mv into it, write the keys file", "project", `ln -s ../.ssh plink && mv a.txt plink && echo k >> plink/authorized_keys`, "block"},
		{"move the disk keys link onto the made link, write", "project", `ln -sfn README.md plink && mv keylink plink && echo k >> plink`, "block"},
		{"link to the keys file made after the move, write", "project", `mv a.txt plink; ln -sfn ../.ssh/authorized_keys plink; echo k >> plink`, "block"},
		{"pathlib hardlink_to the keys file", "project", `python3 -c "import pathlib; pathlib.Path('kl6').hardlink_to('../.ssh/authorized_keys'); open('kl6','a').write('k')"`, "block"},
		{"pathlib symlink_to the keys link", "project", `python3 -c "import pathlib; pathlib.Path('kl6').symlink_to('keylink'); open('kl6','a').write('k')"`, "block"},
		{"pathlib from-import symlink_to the keys file", "project", `python3 -c "from pathlib import Path; Path('kl6').symlink_to('../.ssh/authorized_keys'); open('kl6','a').write('k')"`, "block"},
		{"Path of another module", "project", `python3 -c "import foo; foo.Path('kl6').symlink_to('../.ssh/authorized_keys'); open('kl6','a').write('k')"`, "block"},
		{"pathlib.Path without import pathlib", "project", `python3 -c "pathlib.Path('kl6').symlink_to('../.ssh/authorized_keys'); open('kl6','a').write('k')"`, "block"},
	})
}
