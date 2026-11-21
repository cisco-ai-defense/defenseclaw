// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fu12TierCells are the five packs the S7 rules train asserts: the per-user
// default, permissive and strict packs, and the managed default and strict
// packs behind a managed hook peer.
var fu12TierCells = [...]string{"default", "permissive", "strict", "managed", "managed-strict"}

// fu12TierRow is one command and its verdict per cell of fu12TierCells. A
// want of "!block" accepts allow or alert.
type fu12TierRow struct {
	id, command string
	want        [5]string
}

const fu12Never = "!block"

var (
	fu12UnknownTier = [5]string{"alert", "alert", "block", "alert", "block"}
	fu12BlockAll    = [5]string{"block", "block", "block", "block", "block"}
	fu12NoBlock     = [5]string{fu12Never, fu12Never, fu12Never, fu12Never, fu12Never}
)

func fu12TierVerdicts(t *testing.T, connector string, rows []fu12TierRow) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell routes")
	}
	home, _ := shellProtectedFileHome(t)
	work := filepath.Join(home, "x")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		for i, cell := range fu12TierCells {
			posture, managed := cell, false
			switch cell {
			case "managed":
				posture, managed = "default", true
			case "managed-strict":
				posture, managed = "strict", true
			}
			action, rules := shellProtectedFileRoute(t, home, work, connector, posture, managed, row.command)
			want := row.want[i]
			if want == fu12Never && action != "block" || action == want {
				continue
			}
			t.Errorf("%s %s %s: %q -> %s %v, want %s", connector, row.id, cell, row.command, action, rules, want)
		}
	}
}

// rel-1-0-10:GAP-0571: a link made, renamed and removed in a folder named by
// a variable writes through no link; the write through a link to a protected
// file keeps its verdict.
var gap0571Rows = []fu12TierRow{
	{"P1", "export W=$HOME/x; cd $W && ln -s f.txt lk1 && mv lk1 lk2 && rm lk2 && echo ok", fu12NoBlock},
	{"P8", "cd $W && ln -s f.txt lk1 && mv lk1 lk2 && rm lk2", fu12NoBlock},
	{"P4", "export W=$HOME; cd $W && ln -s .ssh/authorized_keys lk1 && echo k >> lk1", fu12BlockAll},
	{"P5", "export W=$HOME/.ssh; cd $W && ln -s authorized_keys lk1 && mv lk1 lk2 && echo k >> lk2", fu12BlockAll},
}

// rel-1-0-10:GAP-0747: a proven write to DefenseClaw state alerts in the
// default, permissive and managed default packs and blocks in strict and
// managed-strict (ONE BOUND RULE, S7 lead 2026-11-14T23:55Z); a read of it is
// no write.
var gap0747Rows = []fu12TierRow{
	{"S1", "echo 'mode: observe' >> ~/.defenseclaw/config.yaml", fu12UnknownTier},
	{"S2", "rm ~/.defenseclaw/audit.db", fu12UnknownTier},
	{"S3", "cat ~/.defenseclaw/config.yaml", fu12NoBlock},
}

// rel-1-0-10:GAP-0843 and GAP-1536: a command that names authorized_keys
// only in statements that read it, beside a program the scan has no write
// model of, a pipe stage or a backup redirect, is the unknown tier. A name
// handed on ($_), a write through the unknown program to the file, tee -a,
// an append and a sink in ~/.ssh keep the block in every pack (as on rel).
// Q2 and Q4 are the unknown tier behind a managed hook peer too: the
// client's carried protected decision (GAP-0415) is the same unknown-program
// reading, so the managed default alerts like the per-user default and
// managed-strict blocks (owner ruling 2026-11-21, rel-1-0-10:GAP-1611/1698;
// 1.0.10 blocked in the managed default).
var gap0843Rows = []fu12TierRow{
	{"Q2", "wc -l ~/.ssh/authorized_keys && $TOOL > /tmp/o3report.txt", fu12UnknownTier},
	{"Q4", "cat ~/.ssh/authorized_keys | python3 -c \"$CODE\" > /tmp/o3o", fu12UnknownTier},
	{"Q5", "cat ~/.ssh/authorized_keys > /tmp/keys.bak", fu12UnknownTier},
	{"T1", "ls ~/.ssh/authorized_keys; cp /tmp/k $_", fu12BlockAll},
	{"T2", "wc -l ~/.ssh/authorized_keys && $TOOL > ~/.ssh/authorized_keys", fu12BlockAll},
	{"T3", "cat ~/.ssh/authorized_keys | tee -a ~/.ssh/authorized_keys", fu12BlockAll},
	{"C1", "cat k.pub >> ~/.ssh/authorized_keys", fu12BlockAll},
	{"R1", "cat ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.new", fu12BlockAll},
	{"R2", "cat ~/.ssh/authorized_keys | python3 -c \"$CODE\" > ~/.ssh/o3o", fu12BlockAll},
	// S7 lead ruling 2026-11-19: ls KEYS | cpio -pdl d copies the keys file
	// (a cpio pass-through), the block of c8090b1056 in every tier; a digest
	// of it into a report is the GAP-1536 unknown tier.
	{"R3", "ls ~/.ssh/authorized_keys | cpio -pdl d; echo k >> d/notes.txt", fu12BlockAll},
	{"Q6", "sha256sum ~/.ssh/authorized_keys > keys.sum", fu12UnknownTier},
}

func TestGAP0571LinkRenameRemoveKeepsTiersClaudeCode(t *testing.T) {
	fu12TierVerdicts(t, "claudecode", gap0571Rows)
}

func TestGAP0571LinkRenameRemoveKeepsTiersCodex(t *testing.T) {
	fu12TierVerdicts(t, "codex", gap0571Rows)
}

func TestGAP0747StateWriteIsBoundTierClaudeCode(t *testing.T) {
	fu12TierVerdicts(t, "claudecode", gap0747Rows)
}

func TestGAP0747StateWriteIsBoundTierCodex(t *testing.T) {
	fu12TierVerdicts(t, "codex", gap0747Rows)
}

func TestGAP0843KeyMentionBesideUnknownProgramIsUnknownTierClaudeCode(t *testing.T) {
	fu12TierVerdicts(t, "claudecode", gap0843Rows)
}

func TestGAP0843KeyMentionBesideUnknownProgramIsUnknownTierCodex(t *testing.T) {
	fu12TierVerdicts(t, "codex", gap0843Rows)
}
