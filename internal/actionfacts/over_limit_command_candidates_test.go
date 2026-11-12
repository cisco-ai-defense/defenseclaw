// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// TestOverLimitCommandWithTwinReadsOnlyConditionalCandidates pins that a
// command padded with white space, which every rule judges as its twin, adds
// the content-rule target of one reading only: a variable that an assignment
// which may not run (a && x=v, a || x=v) can leave a protected file in. A
// definite assignment and a direct target are left to the twin, and a chain
// whose candidates are all ordinary names no target.
func TestOverLimitCommandWithTwinReadsOnlyConditionalCandidates(t *testing.T) {
	const lib = "echo /usr/local/lib/libreview.so"
	pad := strings.Repeat(" ", 300000)
	for _, c := range []struct {
		name, command, class string
	}{
		{"protected first candidate", "true && P=/etc/ld.so.preload || P=/tmp/ok;" + pad + lib + " >> $P", "global-preload"},
		{"protected second candidate", "true && P=/tmp/ok || P=/etc/ld.so.preload;" + pad + lib + " >> $P", "global-preload"},
		{"padding inside the write", "true && P=/etc/ld.so.preload || P=/tmp/ok; " + lib + pad + ">> $P", "global-preload"},
		{"ordinary candidates", "true && P=/tmp/ok1 || P=/tmp/ok2;" + pad + lib + " >> $P", ""},
		{"three ordinary candidates", "true && P=/tmp/ok1 || P=/tmp/ok2 || P=/tmp/ok3;" + pad + lib + " >> $P", ""},
		{"definite protected binding", "P=/etc/ld.so.preload;" + pad + lib + " >> $P", ""},
		{"direct protected target", lib + pad + " >> /etc/ld.so.preload", ""},
		{"conditional binding replaced by a definite one", "true && P=/etc/ld.so.preload;P=/tmp/ok;" + pad + lib + " >> $P", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			input, facts := overLimitCommandInput(t, "exec_command", c.command)
			if _, bounded := OverLimitCommandBoundedTwin(input, facts); !bounded {
				t.Fatal("the command has no bounded twin")
			}
			class, ok := OverLimitCommandContentTarget(input, facts)
			if class != c.class || ok != (c.class != "") {
				t.Fatalf("class = %q, %t; want %q", class, ok, c.class)
			}
		})
	}
}
