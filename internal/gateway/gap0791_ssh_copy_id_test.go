// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// GAP-0791 (review s7-g596brev of s7/sshfp, pre-existing on rel):
// ssh-copy-id to this machine installs the key in an authorized_keys file of
// this host without naming the file. Rows Q01 and Q10 allow on rel in all
// five tiers; C45 C62 Q11 block on rel only through the ls ~/.ssh mention.
// A loopback destination is the keys write in every tier; a remote host is
// not, and the plain reads stay allowed.
func TestGAP0791SSHCopyIDToThisHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	sshfp2Run(t, home, []sshfp2Row{
		{"Q01 ssh-copy-id localhost", cwd, "ssh-copy-id -i ~/k.pub localhost", sshfp2Keys, sshfp2Block},
		{"Q10 ssh-copy-id me@localhost", cwd, "ssh-copy-id -i ~/k.pub me@localhost", sshfp2Keys, sshfp2Block},
		{"Q11 ssh-copy-id -f 127.0.0.1 after a listing", cwd, "ls ~/.ssh/authorized_keys; ssh-copy-id -f -i ~/k.pub 127.0.0.1", sshfp2Keys, sshfp2Block},
		{"Q19 ssh-copy-id with a port and ::1", cwd, "ssh-copy-id -p 2222 -i ~/k.pub 'u@[::1]'", sshfp2Keys, sshfp2Block},
		{"Q20 inside bash -c", cwd, "bash -c 'ssh-copy-id -i ~/k.pub localhost'", sshfp2Keys, sshfp2Block},
		{"Q21 loopback range", cwd, "ssh-copy-id -i ~/k.pub 127.0.1.5", sshfp2Keys, sshfp2Block},
		// Benign twins: a remote host, the plain reads, an unrelated tool.
		{"Q02 remote host after a listing", cwd, "ls ~/.ssh; ssh-copy-id -i ~/k.pub remotehost.example.org", "", sshfp2Allow},
		{"Q22 remote ip", cwd, "ssh-copy-id -i ~/k.pub deploy@203.0.113.9", "", sshfp2Allow},
		{"Q23 ssh to localhost is no key install", cwd, "ssh localhost uptime", "", sshfp2Allow},
		{"Q24 plain listing", cwd, "ls ~/.ssh; ssh -V", "", sshfp2Allow},
	})
}
