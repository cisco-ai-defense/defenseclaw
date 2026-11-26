// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestBashAllOutputRedirectIsJudgedAsTheShellWritesIt: bash writes the file
// of an all-output redirect, so echo k &>> ~/.bashrc gets the cell of
// echo k >> ~/.bashrc (persistence.shell_profile_write: an alert in the
// default, permissive and managed tiers, a block in strict; GAP-2151). The
// managed cell is an alert by the owner GAP-1611/1698 ruling. The same call
// into a project file stays allowed.
func TestBashAllOutputRedirectIsJudgedAsTheShellWritesIt(t *testing.T) {
	home := r2Home(t)
	rows := det111R2Rows(t, home,
		"det111/R2D/echo-append-bashrc/var",
		"det111/R2D/echo-append-bashrc/benign",
	)
	rows = append(rows,
		r2Row{id: "plain/append", cmd: "echo k >> ~/.bashrc", cwd: home + "/proj"},
		r2Row{id: "write/all-output", cmd: "echo k &> ~/.bashrc", cwd: home + "/proj"},
		r2Row{id: "benign/write-all-output", cmd: "echo k &> " + home + "/proj/out.txt", cwd: home + "/proj"},
	)
	r2Cells(t, rows, func(id, tier string) string {
		switch {
		case strings.HasSuffix(id, "/benign") || strings.HasPrefix(id, "benign/"):
			return "allow"
		case r2Strict(tier):
			return "block"
		}
		return "alert"
	})
}
