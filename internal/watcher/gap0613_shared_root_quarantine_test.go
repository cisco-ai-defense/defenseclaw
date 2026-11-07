// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0613: on a folder two connectors load, a skill denied by the second
// connector rule whose quarantine fails stays in the folder. The journal says
// so for the connector whose rule denied it as well as for the event owner,
// so neither is left without the install block.
func TestGAP0613SharedRootDeniedSkillWhoseQuarantineFailsIsJournaledForTheDenyingConnector(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as a non-root user")
	}
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.AssetPolicy = config.DefaultAssetPolicy()
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "denied-skill", Connector: "codex"}}
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{skillDir: "amp"})
	w.SetRootConsumers([]RootConsumer{{"skill", skillDir, "amp"}, {"skill", skillDir, "codex"}})
	path := filepath.Join(skillDir, "denied-skill")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("---\nname: denied-skill\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.QuarantineDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.QuarantineDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg.QuarantineDir, 0o700) })

	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "denied-skill", Path: path, Connector: "amp", Timestamp: time.Now()})
	if res.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %q, want blocked", res.Verdict)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("expected the skill to stay in place: %v", err)
	}
	for _, connector := range []string{"amp", "codex"} {
		entry, err := store.GetActionForConnector("skill", "denied-skill", connector)
		if err != nil || entry == nil || entry.Actions.Install != "block" || !strings.HasPrefix(entry.Reason, "quarantine failed: ") {
			t.Errorf("%s journal = %+v (err %v), want install block with quarantine failed", connector, entry, err)
		}
	}
}
