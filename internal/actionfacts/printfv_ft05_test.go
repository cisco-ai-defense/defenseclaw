// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// rel-1-0-10:GAP-1044. A printf -v name the walk cannot read may be any name,
// as for read: it may be HOME, USER or LOGNAME.
func TestGAP1044PrintfVUnreadableNameBindsEvery(t *testing.T) {
	for _, row := range []struct {
		command string
		user    []string
		home    bool
	}{
		{"printf -v $N v", []string{"USER", "LOGNAME"}, true},
		{"printf -v \"$N\" v", []string{"USER", "LOGNAME"}, true},
		{"printf -v HOME v", nil, true},
		{"printf -v OTHER v", nil, false},
		{"printf %s v", nil, false},
	} {
		file, ok := shellparse.Parse(row.command)
		if !ok || len(file.Stmts) != 1 {
			t.Fatalf("%q does not parse as one statement", row.command)
		}
		call, _ := file.Stmts[0].Cmd.(*syntax.CallExpr)
		got := CallBindsUserNames(call)
		slices.Sort(got)
		want := slices.Clone(row.user)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("CallBindsUserNames(%q) = %v, want %v", row.command, got, want)
		}
		if got := simpleCallReadsHome(call); got != row.home {
			t.Errorf("simpleCallReadsHome(%q) = %v, want %v", row.command, got, row.home)
		}
	}
}
