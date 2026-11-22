// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestGAP1219ReviewR3Binders: review round 3 of s7/g1219fix. An indexed
// printf -v destination (V06) and a mapfile or readarray callback (V07)
// bind a name in the receiving shell, so the twin is unread; a [[ ]] test
// binds nothing unless an arithmetic operand can assign (C02).
func TestGAP1219ReviewR3Binders(t *testing.T) {
	for _, row := range []struct {
		name, body string
		unread     bool
	}{
		{"V06", "printf -v D[0] %s /tmp/x; rm -rf $D/*", true},
		{"V06-quoted", "printf -v 'D[0]' %s /tmp/x; rm -rf $D/*", true},
		{"V06-fused", "printf -vD[0] %s /tmp/x; rm -rf $D/*", true},
		{"V06-read", "read -r D[0] < /etc/hostname; rm -rf $D/*", true},
		{"V07", "mapfile -C 'D=/tmp/x; :' -c 1 L < /etc/hostname; rm -rf $D/*", true},
		{"V07-cluster", "readarray -tC 'D=/tmp/x; :' -c 1 L < /etc/hostname; rm -rf $D/*", true},
		{"A02-arith", "[[ 1 -eq D=1 ]]; rm -rf $D/*", true},
		{"A02-arith-param", "[[ $N -eq 1 ]]; rm -rf $D/*", true},
		{"C02-string", "[[ -n $HOME ]] && echo $HOME", false},
		{"C02-file", "[[ -f $HOME/.bashrc ]] && echo $HOME", false},
		{"C02-number", "[[ 2 -gt 1 ]] && echo $HOME", false},
		{"C02-length", "[[ ${#HOME} -gt 1 ]] && echo $HOME", false},
		{"mapfile-plain", "mapfile -t L < /etc/hostname; echo $HOME", false},
	} {
		command := "cat <<EOF | bash\n" + row.body + "\nEOF"
		_, _, _, unread := RunTimeShellTwin(command)
		if unread != row.unread {
			t.Errorf("%s: unread=%t, want %t (%q)", row.name, unread, row.unread, command)
		}
	}
}
