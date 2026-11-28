// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package guardrail

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A junction in a rule pack that leads out of the pack fails the rebase, as a
// symbolic link out of it does: the 1.0 copy would take content from outside
// the pack. filepath.EvalSymlinks left the junction unfollowed, so it read as
// inside (rel-1-0-10:GAP-2185).
func TestGAP2185RulePackRebaseRefusesAJunctionOutOfThePack(t *testing.T) {
	base := gap2185Base(t)
	pack := filepath.Join(base, "pack")
	outside := filepath.Join(base, "outside")
	gap2185WriteFile(t, filepath.Join(pack, "rules.yaml"), "rules: []\n")
	gap2185WriteFile(t, filepath.Join(outside, "extra.yaml"), "rules: []\n")
	gap2185Junction(t, filepath.Join(pack, "ext"), outside)
	if _, _, err := readRulePackTree(pack); err == nil || !strings.Contains(err.Error(), "outside the rule pack") {
		t.Fatalf("readRulePackTree with a junction out of the pack = %v; want the outside-the-pack refusal", err)
	}
}

// A junction in a rule pack to a folder inside the pack is followed, as a
// symbolic link inside it is: the copy holds the stray YAML file where the
// link was, and not again at the folder the link names (rel-1-0-10:GAP-2185).
func TestGAP2185RulePackRebaseFollowsAJunctionInsideThePack(t *testing.T) {
	base := gap2185Base(t)
	pack := filepath.Join(base, "pack")
	gap2185WriteFile(t, filepath.Join(pack, "rules.yaml"), "rules: []\n")
	gap2185WriteFile(t, filepath.Join(pack, "real", "more.yaml"), "rules: []\n")
	gap2185Junction(t, filepath.Join(pack, "alias"), filepath.Join(pack, "real"))
	files, linked, err := readRulePackTree(pack)
	if err != nil {
		t.Fatalf("readRulePackTree with a junction inside the pack = %v; want nil", err)
	}
	if len(linked) != 1 || !strings.HasPrefix(linked[0], "alias -> ") {
		t.Errorf("linked = %q; want the alias junction", linked)
	}
	if _, ok := files["alias/more.yaml"]; !ok {
		t.Errorf("files = %v; want alias/more.yaml", gap2185Keys(files))
	}
	if _, ok := files["real/more.yaml"]; ok {
		t.Errorf("files = %v; want real/more.yaml held only where the link was", gap2185Keys(files))
	}
}

func gap2185Keys(files map[string][]byte) []string {
	var out []string
	for key := range files {
		out = append(out, key)
	}
	return out
}

func gap2185WriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
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
