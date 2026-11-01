// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestInterpreterAndPowerShellLinkSpellingsOfTheKeysFile pins the link
// spellings of p0-round GAP-1524: a hard or symbolic link made by an
// interpreter (from os import link, import os as o, node linkSync, perl
// link, ruby File.link) or by PowerShell New-Item with the -Type alias, the
// -it or -I abbreviation or -ItemType:value, to the keys file and then
// written through blocks per-user and managed; the same link of a project
// file stays an ordinary write.
func TestInterpreterAndPowerShellLinkSpellingsOfTheKeysFile(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"py from-import link", "project", `python3 -c "from os import link; link('../.ssh/authorized_keys','kl'); open('kl','a').write('k')"`, "block"},
		{"py import os as o", "project", `python3 -c "import os as o; o.link('../.ssh/authorized_keys','kl'); open('kl','a').write('k')"`, "block"},
		{"node linkSync", "project", `node -e "require('fs').linkSync('../.ssh/authorized_keys','kl'); require('fs').appendFileSync('kl','k')"`, "block"},
		{"perl link", "project", `perl -e 'link("../.ssh/authorized_keys","kl"); open(F,">>kl"); print F "k"'`, "block"},
		{"ruby File.link", "project", `ruby -e 'File.link("../.ssh/authorized_keys","kl"); File.open("kl","a"){|f| f.write("k")}'`, "block"},
		{"pwsh New-Item -Type HardLink", "project", `pwsh -NoProfile -Command "New-Item -Type HardLink -Path kl -Target ../.ssh/authorized_keys; Add-Content kl k"`, "block"},
		{"pwsh ni -it HardLink", "project", `pwsh -NoProfile -Command "ni -it HardLink -Path kl -Value ../.ssh/authorized_keys; Add-Content kl k"`, "block"},
		{"pwsh New-Item -ItemType:HardLink", "project", `pwsh -NoProfile -Command "New-Item -ItemType:HardLink -Path kl -Target ../.ssh/authorized_keys; Add-Content kl k"`, "block"},
		{"pwsh New-Item -I SymbolicLink", "project", `pwsh -NoProfile -Command "New-Item -I SymbolicLink -Path kl -Target ../.ssh/authorized_keys; Add-Content kl k"`, "block"},
		{"pwsh benign hardlink README", "project", `pwsh -NoProfile -Command "New-Item -Type HardLink -Path kl -Target README.md; Add-Content kl k"`, "allow"},
		{"py from-import benign", "project", `python3 -c "from os import link; link('README.md','kl'); open('kl','a').write('k')"`, "allow"},
	})
}
