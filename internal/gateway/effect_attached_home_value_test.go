// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestShortOptionAttachedHomeValueIsThePath: the shell expands $HOME
// anywhere in a word, so sort -o"$HOME/.bashrc" writes ~/.bashrc as
// sort -o ~/.bashrc does: persistence.shell_profile_write, an alert in the
// default, permissive and managed tiers and a block in strict (GAP-2152).
// The tilde of sort -o~/.bashrc is not at the start of its word, so bash
// leaves it as it is and sort writes ./~/.bashrc: that pinned row stays
// allowed, as do the project-file twins.
func TestShortOptionAttachedHomeValueIsThePath(t *testing.T) {
	home := r2Home(t)
	rows := det111R2Rows(t, home,
		"det111/R2D/sort-short-output-home/var",
		"det111/R2D/sort-short-output-home/benign",
		"det111/R2D/sort-short-output/var",
		"det111/R2D/sort-short-output/benign",
	)
	rows = append(rows,
		r2Row{id: "var/unquoted", cmd: "sort -o$HOME/.bashrc /tmp/x", cwd: home + "/proj"},
		r2Row{id: "var/braced", cmd: "sort -o${HOME}/.bashrc /tmp/x", cwd: home + "/proj"},
		r2Row{id: "plain/separate", cmd: "sort -o ~/.bashrc /tmp/x", cwd: home + "/proj"},
	)
	r2Cells(t, rows, func(id, tier string) string {
		switch {
		case strings.HasSuffix(id, "/benign") || id == "det111/R2D/sort-short-output/var":
			return "allow"
		case r2Strict(tier):
			return "block"
		}
		return "alert"
	})
}
