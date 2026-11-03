// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// A link the command makes in the project and a move into the folder that
// holds its target is judged the same by a managed gateway that cannot read
// the user home as by a per-user gateway (rel-1-0-6:GAP-0091, the managed
// W07 leg): ln -s build/out bin; mv bin build is allowed with and without a
// trailing slash, and a move of an ordinary file there too. A link the
// command makes to the keys file or the SSH folder and a write through it,
// also after a move, still block in both.
func TestSelfProtLinkMoveIntoTargetFolderManagedMatchesPerUser(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"M01", `ln -s build/out bin; mv bin build/`, "allow"},
		{"M02", `ln -s build/out bin; mv bin build`, "allow"},
		{"M06", `ln -s build/out bin; mv a.txt build/`, "allow"},
		{"M07", `ln -s build/out bin; mv a.txt build`, "allow"},
		{"M08", `mkdir -p build/out && ln -s build/out bin; mv bin build/`, "allow"},
		{"M09", `ln -s build/out bin && mv bin build`, "allow"},
		{"M10", `ln -s build/out bin; mv bin bin2`, "allow"},
		{"M03", `ln -s ~/.ssh/authorized_keys k; mv k build/; echo x >> build/k`, "block"},
		{"M04", `ln -s ~/.ssh/authorized_keys k; mv k build; echo x >> build/k`, "block"},
		{"M05", `ln -s build/out bin; mv bin ../.ssh/`, "block"},
		{"M11", `ln -s ../.ssh k; mv a.txt build; cp b.txt k/authorized_keys`, "block"},
		{"M12", `ln -s build/keylink bin; mv keylink build; echo x >> bin`, "block"},
	}, "claudecode", "codex")
}
