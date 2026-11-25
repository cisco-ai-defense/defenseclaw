// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A plugin path a Devin store record names, that is a junction inside an
// installed plugin and leads out of the store, is judged where it leads:
// the store walk does not go through it. filepath.EvalSymlinks left the
// junction unfollowed, so the record read as covered by the walk and the
// plugin outside was never judged (rel-1-0-10:GAP-2185).
func TestGAP2185GuardJudgesARecordedDevinPluginBehindAJunction(t *testing.T) {
	req := guardRequest(t, "devin", config.ForeignHooksRemove)
	store := filepath.Join(req.Home, ".local", "share", "devin", "cli", "plugins")
	installed := filepath.Join(store, "cache", "mkt", "host", "1.0.0")
	writeFile(t, filepath.Join(installed, ".devin-plugin", "plugin.json"), `{"name": "host"}`)
	outside := filepath.Join(req.Home, "src", "outside-plugin")
	writeFile(t, filepath.Join(outside, "plugin.json"), `{"name": "outside", "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./x.sh"}]}]}}`)
	nested := filepath.Join(installed, "nested")
	gap2185Junction(t, nested, outside)
	writeFile(t, filepath.Join(store, "lock.json"), `{"plugins": {"nested": {"source": `+jsonString(nested)+`}}}`)

	decision := EvaluateForeignHooks(req)
	if !decision.Deny || len(decision.Findings) != 1 {
		t.Fatalf("the Devin plugin behind a junction must be judged and deny: %+v", decision)
	}
}

// A working folder that is a junction is walked under its target too, so
// the files at the root of the repository it leads into are seen
// (rel-1-0-10:GAP-2185).
func TestGAP2185ProjectDirsWalkAJunctionWorkingFolderWhereItLeads(t *testing.T) {
	base := gap2185Base(t)
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(base, "elsewhere", "work")
	gap2185Junction(t, cwd, filepath.Join(repo, "src"))
	dirs, err := projectDirs(cwd, []string{base}, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, dir := range dirs {
		if strings.EqualFold(dir, repo) {
			found = true
		}
	}
	if !found {
		t.Errorf("projectDirs(junction cwd) = %q; want the repository root %q in it", dirs, repo)
	}
}

func gap2185Base(t *testing.T) string {
	t.Helper()
	base, err := winpath.EvalLinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return base
}

func gap2185Junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
}
