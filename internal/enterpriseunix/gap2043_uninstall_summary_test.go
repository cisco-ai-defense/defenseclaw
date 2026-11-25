// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-2043 (GitHub #1452): the uninstall summary said an account's files
// were put back "byte for byte" instead of naming what it put back. It names
// the hook scripts and settings, the connector backups and lock, and the
// agent settings, once per restored account and for no other account.
func TestGAP2043UninstallSummaryNamesWhatItPutsBack(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
	uid := os.Getuid()
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath), fmt.Sprintf(
		`{"accounts":[{"user":"restored","uid":%d,"home":"/Users/restored"},{"user":"plain","uid":%d,"home":"/Users/plain"}]}`, uid, uid))
	writeHostFile(t, h, "/Users/restored/.defenseclaw/config.yaml", "guardrail: {}\n")
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{Stdout: []byte(`{"ok":true,"removed":2,"own_install_restored":["restored"]}`)}, nil
	}}
	done := h.run(Options{Action: ActionUninstall})
	requireOK(t, done)
	changes := strings.Join(done.Changes, "\n")
	for _, want := range []string{
		"put back the own DefenseClaw setup of user restored",
		"hook scripts and hook settings (~/.defenseclaw/hooks)",
		"connector backups and hook contract lock",
		"agent settings those backups name",
	} {
		if !strings.Contains(changes, want) {
			t.Errorf("uninstall summary does not name %q:\n%s", want, changes)
		}
	}
	if strings.Contains(changes, "byte for byte") {
		t.Errorf("uninstall summary says byte for byte instead of what it put back:\n%s", changes)
	}
	if strings.Count(changes, "put back the own DefenseClaw setup of user") != 1 || strings.Contains(changes, "of user plain") {
		t.Errorf("the put-back line must name only the restored account, once:\n%s", changes)
	}
}
