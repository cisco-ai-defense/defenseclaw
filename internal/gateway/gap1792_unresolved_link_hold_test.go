// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP1792UnresolvedLinkHoldStaysAdvisory(t *testing.T) {
	home := filepath.Join(t.TempDir(), "s7c", "fx", "Users", "synthetic")
	cwd := filepath.Join(home, "Desktop", "synthetic-work", "repo")
	out := "/tmp/synthetic-trial"
	for _, dir := range []string{filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := `rm -rf ` + out + ` && mkdir -p ` + out + ` && cd ` + cwd + ` && grep -E "\\.(ts|tsx|mjs|mts)$" /tmp/synthetic-files.txt > /tmp/synthetic-codefiles.txt && rsync -a --files-from=/tmp/synthetic-codefiles.txt ./ ` + out + `/ && cd ` + out + ` && python3 /tmp/synthetic-tools/clean_refs.py $(cat /tmp/synthetic-codefiles.txt) | tail -3 && diff -ru ` + cwd + `/src ` + out + `/src | grep "^[-+]" | grep -v "^+++" | head -20`
	input := actionfacts.Input{Tool: "Bash", Command: command, ActiveHome: home, CWD: cwd, DialectHint: actionfacts.DialectPOSIX}
	facts := actionfacts.Analyze(input)
	installDefaultProfileConnector(t, "claudecode")
	oldGeneration := liveGeneration.Load()
	cfg := &config.Config{}
	cfg.Guardrail.Cascade.SetLane(config.CascadeLaneEffects, "on")
	liveGeneration.Store(&Generation{Config: cfg})
	t.Cleanup(func() { liveGeneration.Store(oldGeneration) })
	request := shadowLiveRequest(command)
	request.Connector = "claudecode"
	request.Input = input
	request.LegacyText = command
	request.targetMemo = hookpaths.NewTargetMemo()
	var held unprovenWrite
	request.unprovenTarget = &held
	if !trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
		links := hookpaths.CommandLinksWithFacts(input.Tool, command, cwd, home, nil)
		t.Fatalf("synthetic link-scope hold was not reproduced: paths=%d issues=%v opaque=%v opaque-root=%v", len(facts.Paths), facts.Parse.Issues, links.OpaqueTargetWithFacts(out, true, nil), links.OpaqueTargetWithFacts(out, false, nil))
	}
	if held.class != hookpaths.UnprovenLinkUnread || !filepath.IsAbs(held.operand) || !strings.HasPrefix(held.operand, "/tmp/") {
		t.Fatalf("hold = %q at %q, want an unresolved scoped link target under /tmp", held.class, held.operand)
	}
	if !unprovenSSHKeyHoldIsMaybe(home, held) {
		t.Fatalf("unresolved /tmp link hold was treated as a known protected write: %q", held.operand)
	}
	findings := dispatchTrustedAction(t.Context(), request)
	finding := findingWithID(findings, "persistence.ssh_authorized_keys_command")
	if finding == nil || finding.contributesToEnforcement() {
		t.Fatalf("unresolved synthetic link hold enforced the SSH rule: %+v", finding)
	}
}
