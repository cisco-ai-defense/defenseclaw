// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP1792RsyncDestinationRootIsNotAnAuthorizedKeysWrite(t *testing.T) {
	home := filepath.Join(t.TempDir(), "s7c", "fx", "Users", "synthetic")
	cwd := filepath.Join(home, "Desktop", "synthetic-work", "repo")
	out := filepath.Join(t.TempDir(), "synthetic-trial")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
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
	links := hookpaths.CommandLinksWithFacts(input.Tool, command, cwd, home, nil)
	if links.OpaqueTargetWithFacts(out, false, nil) {
		t.Fatal("a link copied into the destination marked its directory entry as a link")
	}
	if !links.OpaqueTargetWithFacts(filepath.Join(out, "src"), false, nil) {
		t.Fatal("the destination's children lost their uncertain link scope")
	}
	if trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
		t.Fatal("the destination directory was held as an authorized-keys write")
	}
	findings := dispatchTrustedAction(t.Context(), request)
	if finding := findingWithID(findings, "persistence.ssh_authorized_keys_command"); finding != nil {
		t.Fatalf("a copy into an ordinary directory raised the SSH rule: %+v", finding)
	}
}
