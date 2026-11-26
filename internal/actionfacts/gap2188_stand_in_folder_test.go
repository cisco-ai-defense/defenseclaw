// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package actionfacts

import (
	"slices"
	"strings"
	"testing"
)

// A relative nsenter working directory is based at the caller's folder. When
// the call is judged in a stand-in folder (Input.StandInCWD) the walk does not
// know that folder, so the child starts in an unknown folder there; a real
// caller folder still places it (rel-1-0-10:GAP-2188, GAP-1482).
func TestGAP2188StandInFolderLeavesRelativeNSEnterChildUnknown(t *testing.T) {
	const standIn = "/var/tmp/defenseclaw-proxy-cwd-1"
	const body = ": >> alice/.defenseclaw/config.yaml"
	for _, row := range []struct {
		id, command, cwd, standIn, wantCWD string
		unknown                            bool
	}{
		{"real caller folder", "nsenter --target=1 --wd=.. sh -c '" + body + "'", "/home/alice", "", "/home", false},
		{"stand-in folder", "nsenter --target=1 --wd=.. sh -c '" + body + "'", standIn, standIn, "", true},
		{"stand-in short option", "nsenter --target=1 -w.. sh -c '" + body + "'", standIn, standIn, "", true},
		{"stand-in same folder", "nsenter --target=1 --wd=. sh -c '" + body + "'", standIn, standIn, "", true},
		{"parent of the stand-in", "cd .. && nsenter --target=1 --wd=.. sh -c '" + body + "'", standIn, standIn, "", true},
		{"real folder after cd", "cd /home/alice && nsenter --target=1 --wd=.. sh -c '" + body + "'", standIn, standIn, "/home", false},
		{"absolute folder", "nsenter --target=1 --wd=/home sh -c '" + body + "'", standIn, standIn, "/home", false},
	} {
		t.Run(row.id, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: row.command, CWD: row.cwd, StandInCWD: row.standIn}
			got := SimpleCommands(input, Analyze(input))
			if !slices.ContainsFunc(got, func(s SimpleCommand) bool {
				return s.Text == body && s.CWD == row.wantCWD && s.UnresolvedFolder == row.unknown
			}) {
				t.Errorf("no body in folder %q unknown=%v: %+v", row.wantCWD, row.unknown, got)
			}
			// Under a stand-in, the body is never placed in a folder the
			// stand-in's parents name (the temp folder): that is no place of
			// the caller's.
			if row.unknown && slices.ContainsFunc(got, func(s SimpleCommand) bool {
				return s.Text == body && s.CWD != "" && s.CWD != standIn && strings.HasPrefix(standIn, strings.TrimSuffix(s.CWD, "/")+"/")
			}) {
				t.Errorf("body placed above the stand-in folder: %+v", got)
			}
		})
	}
}
