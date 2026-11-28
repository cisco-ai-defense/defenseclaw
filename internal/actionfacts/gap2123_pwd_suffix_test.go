// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

func TestGAP2123KnownPWDSuffixRedirect(t *testing.T) {
	vars := map[string]string{"PWD": "/home/det111/proj", "HOME": "/home/det111"}
	const home, cwd = "/home/det111", "/home/det111/proj"
	tests := []struct {
		name, command, want string
		resolved            bool
	}{
		{"marker", "echo y >> ${PWD%/proj}/.bashrc", "echo y >> '/home/det111/.bashrc'", true},
		{"lookalike", "echo y >> ${PWD%/proj}/proj/.bashrc.fixture", "echo y >> '/home/det111/proj/.bashrc.fixture'", true},
		{"safe-content", "echo 'export PATH=$HOME/bin:$PATH' >> ${PWD%/proj}/.bashrc", "", false},
		{"glob-pattern", "echo y >> ${PWD%/pr*}/.bashrc", "", false},
		{"other-operator", "echo y >> ${PWD##*/}/.bashrc", "", false},
		{"non-redirect", "printf %s ${PWD%/proj}/.bashrc", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := simpleResolvedVariables(test.command, vars, home, cwd)
			if ok != test.resolved || ok && got != test.want {
				t.Fatalf("resolution=%t, target match=%t; want resolution=%t", ok, got == test.want, test.resolved)
			}
		})
	}
	// The parity proof analyzes all known redirect targets at once. More
	// than four targets stay unresolved without recursive control analysis.
	multi := "echo y >> ${PWD%/proj}/.bashrc >> ${PWD%/proj}/.zshrc"
	if got, ok := simpleResolvedVariables(multi, vars, home, cwd); !ok || strings.Contains(got, "${PWD%") {
		t.Fatal("two known suffix targets were not resolved")
	}
	overCap := "echo y" + strings.Repeat(" >> ${PWD%/proj}/.bashrc", 5)
	if _, ok := simpleResolvedVariables(overCap, vars, home, cwd); ok {
		t.Fatal("over-cap suffix targets resolved")
	}
	for _, pwd := range []string{"/home/det111/pr*j/proj", "/home/det111/my proj/proj", "//host/share/proj"} {
		unsafeVars := map[string]string{"PWD": pwd, "HOME": "/home/det111"}
		if _, ok := simpleResolvedVariables("echo y >> ${PWD%/proj}/.bashrc", unsafeVars, home, cwd); ok {
			t.Fatal("nonliteral PWD resolved")
		}
	}
}
