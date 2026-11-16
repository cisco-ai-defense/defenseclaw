// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// rel-1-0-6:GAP-0601 review 5: a call binds USER or LOGNAME only when the
// shell does. A prompt, a timeout or a descriptor is not a name, an eval or
// trap of code that binds nothing binds nothing, and code the walk cannot
// read may bind either.
func TestCallBindsUserNamesReadsTheBindingNotTheMention(t *testing.T) {
	for _, row := range []struct {
		command string
		want    []string
	}{
		{"read USER", []string{"USER"}},
		{"read -r LOGNAME", []string{"LOGNAME"}},
		{"read -r -p prompt USER LOGNAME", []string{"USER", "LOGNAME"}},
		{"read -p USER OTHER", nil},
		{"read -t 5 -n 1 OTHER", nil},
		{"read -u 3 USER", []string{"USER"}},
		{"read -rp USER OTHER", nil},
		{"read -a USER", []string{"USER"}},
		{"read OTHER USER", []string{"USER"}},
		{"read -- USER", []string{"USER"}},
		{"read $name", []string{"USER", "LOGNAME"}},
		{"mapfile -t USER", []string{"USER"}},
		{"readarray -d x -O 1 LOGNAME", []string{"LOGNAME"}},
		{"mapfile -C USER OTHER", nil},
		{"printf -v USER x", []string{"USER"}},
		{"printf -v OTHER x", nil},
		{"eval ':'", nil},
		{"eval 'echo USER'", nil},
		{"eval ': # LOGNAME'", nil},
		{"eval 'USER=x'", []string{"USER"}},
		{"eval 'export LOGNAME=x; read OTHER'", []string{"LOGNAME"}},
		{"eval 'read USER'", []string{"USER"}},
		{"eval 'for LOGNAME in a; do :; done'", []string{"LOGNAME"}},
		{"eval $code", []string{"USER", "LOGNAME"}},
		{"eval 'unterminated \"'", []string{"USER", "LOGNAME"}},
		{"trap 'echo USER' EXIT", nil},
		{"trap 'LOGNAME=x' EXIT", []string{"LOGNAME"}},
		{"trap -p", nil},
		{". ./env.sh", []string{"USER", "LOGNAME"}},
		{"source /dev/null", []string{"USER", "LOGNAME"}},
		{"ls USER", nil},
	} {
		file, ok := shellparse.Parse(row.command)
		if !ok || len(file.Stmts) != 1 {
			t.Fatalf("%q does not parse as one statement", row.command)
		}
		call, _ := file.Stmts[0].Cmd.(*syntax.CallExpr)
		got := CallBindsUserNames(call)
		slices.Sort(got)
		want := slices.Clone(row.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("CallBindsUserNames(%q) = %v, want %v", row.command, got, want)
		}
	}
}
