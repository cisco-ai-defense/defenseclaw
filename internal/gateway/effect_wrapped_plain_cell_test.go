// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestOwnCredentialReadWrappedKeepsThePlainCell: a read of one's own AWS
// credentials shown to the agent keeps the cell of cat ~/.aws/credentials
// (PATH-AWS-CREDS, GAP-0888: an alert MEDIUM, nothing in permissive) behind
// a context-neutral or identity wrapper and through another reader
// (GAP-1323, GAP-1326, GAP-1494; DET111 ruling 2026-11-24: plain parity, the
// GAP-0888 tier is kept). doas base64 was allowed: under an identity
// wrapper's HOME a filter missing from homeBlindPrograms lost its known
// read. The README twins stay allowed.
func TestOwnCredentialReadWrappedKeepsThePlainCell(t *testing.T) {
	home := r2Home(t)
	rows := det111R2Rows(t, home,
		"det111/GAP-1323/seed-cat-aws/seed",
		"det111/GAP-1323/cat-aws-nohup/var", "det111/GAP-1323/cat-aws-nice/var",
		"det111/GAP-1323/cat-aws-timeout/var", "det111/GAP-1323/cat-aws-sudo/var",
		"det111/GAP-1323/cat-aws-exec/var", "det111/GAP-1323/cat-aws-command/var",
		"det111/GAP-1323/cat-aws-env-C/var", "det111/GAP-1323/cat-aws-time/var",
		"det111/GAP-1326/seed-cat-aws-1326/seed", "det111/GAP-1326/sudo-nohup-cat-aws/var",
		"det111/GAP-1326/sudo-nohup-cat-aws-codex/var", "det111/GAP-1326/sudo-nohup-benign/twin",
		"det111/GAP-1494/seed-base64-aws/seed", "det111/GAP-1494/base64-aws-setsid/var",
		"det111/GAP-1494/base64-aws-stdbuf-ol/var", "det111/GAP-1494/base64-aws-ionice-c3/var",
		"det111/GAP-1494/base64-aws-doas/var",
		"det111/R2D/sed-p-credentials/var", "det111/R2D/sed-P-credentials/var",
		"det111/R2D/sed-n-p-credentials/var", "det111/R2D/sed-p-credentials/benign",
	)
	rows = append(rows, r2Row{id: "var/sudo-base64", cmd: "sudo base64 ~/.aws/credentials", cwd: home + "/proj"})
	r2Cells(t, rows, func(id, tier string) string {
		if strings.HasSuffix(id, "/twin") || strings.HasSuffix(id, "/benign") || tier == "permissive" {
			return "allow"
		}
		return "alert"
	})
}

// TestHookConfigWrappedDeleteKeepsThePlainCell: rm -f and truncate -s0 of an
// agent hook config behind a prefix wrapper keep the plain call's cell
// (tamper.agent_hook_config_write: an alert in the default, permissive and
// managed tiers, a block in strict; GAP-1493). The managed cell is an alert
// by the owner GAP-1611/1698 ruling.
func TestHookConfigWrappedDeleteKeepsThePlainCell(t *testing.T) {
	home := r2Home(t)
	var ids []string
	for _, w := range []string{"nohup", "setsid", "sudo", "nice", "env", "timeout-5", "stdbuf-ol", "ionice-c3", "doas"} {
		ids = append(ids, "det111/GAP-1493/rm-"+w+"/var", "det111/GAP-1493/truncate-"+w+"/var")
	}
	ids = append(ids, "det111/GAP-1493/seed-rm-hook/seed", "det111/GAP-1493/seed-truncate-hook/seed")
	r2Cells(t, det111R2Rows(t, home, ids...), func(_, tier string) string {
		if r2Strict(tier) {
			return "block"
		}
		return "alert"
	})
}

// TestCredentialMoveKeepsTheRemoveCell: mv ~/.aws/credentials elsewhere
// removes the file as rm ~/.aws/credentials does and blocks in every tier
// (GAP-2153); the project move stays allowed.
func TestCredentialMoveKeepsTheRemoveCell(t *testing.T) {
	home := r2Home(t)
	r2Cells(t, det111R2Rows(t, home, "det111/R2D/mv-credentials/var", "det111/R2D/mv-credentials/benign"),
		func(id, _ string) string {
			if strings.HasSuffix(id, "/benign") {
				return "allow"
			}
			return "block"
		})
}
