// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// GAP-0790 (review s7-g596brev of s7/sshfp edbbaf0773): a bare reader name
// that the same call rebinds is not the system reader. hash -p and alias bind
// the name to another program, and a copy named like the reader in any folder
// (~/bin, /usr/local/bin) can shadow it. The ssh folder these calls name keeps
// rel's block in all five tiers (rows Q03, Q04, Q07, Q09); the plain readers a
// developer really runs stay allowed (GAP-0570, GAP-0715).
func TestGAP0790ReaderNameReboundInTheSameCall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	sshfp2Run(t, home, []sshfp2Row{
		{"Q03 hash -p then ls", cwd, "cp ~/k ~/x && chmod +x ~/x && hash -p ~/x ls && ls ~/.ssh", sshfp2Keys, sshfp2Block},
		{"Q04 alias then ls", cwd, "cp ~/k ~/x && chmod +x ~/x && alias ls=~/x; ls ~/.ssh", sshfp2Keys, sshfp2Block},
		{"Q07 copy named ls in ~/bin", cwd, "cp ~/k ~/bin/ls && chmod +x ~/bin/ls && ls ~/.ssh", sshfp2Keys, sshfp2Block},
		{"Q09 copy named ls in /usr/local/bin", cwd, "cp ~/k /usr/local/bin/ls && chmod +x /usr/local/bin/ls && ls ~/.ssh", sshfp2Keys, sshfp2Block},
		{"Q12 tee named cat in ~/bin", cwd, "tee ~/bin/cat < ~/k >/dev/null; cat ~/.ssh/authorized_keys", sshfp2Keys, sshfp2Block},
		{"Q13 redirect named cat", cwd, "echo x > ~/bin/cat; cat ~/.ssh/authorized_keys", sshfp2Keys, sshfp2Block},
		{"Q14 into a folder keeps the name", cwd, "cp ~/k ~/bin/ && cp ls ~/bin/ && ls ~/.ssh", sshfp2Keys, sshfp2Block},
		// Benign twins: a copy under another name, hash -r, an alias of a
		// program the call does not read with, and a plain reader.
		{"Q15 copy under another name", cwd, "cp ~/k ~/x; ls ~/.ssh; ssh -V", "", sshfp2Allow},
		{"Q16 hash -r then ls", cwd, "hash -r; ls ~/.ssh; ssh -V", "", sshfp2Allow},
		{"Q17 plain ls", cwd, "ls ~/.ssh; ssh -V", "", sshfp2Allow},
		{"Q18 cp of a notes file then cat of the config", cwd, "cp notes.txt notes.bak; cat ~/.ssh/config | head -5; ssh -G localhost", "", sshfp2Allow},
	})
}
