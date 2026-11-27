// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
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

// The absolute-redirect exception still follows a pre-existing link into
// the protected keys file, even when a copied-link scope is unplaced.
func TestGAP1792AbsoluteRedirectAliasToKeysStillBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scope")
	}
	home := filepath.Join(t.TempDir(), "home")
	cwd := filepath.Join(home, "project")
	dest := filepath.Join(t.TempDir(), "trial")
	for _, dir := range []string{cwd, dest, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ordinary", filepath.Join(cwd, "source-link")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(keys, alias); err != nil {
		t.Fatal(err)
	}
	command := `cd ` + cwd + ` && rsync -a --files-from=/tmp/synthetic-list ./ ` + dest + `/ && echo $(cd /tmp && pwd) && grep marker > ` + alias
	input := actionfacts.Input{Tool: "Bash", Command: command, ActiveHome: home, CWD: cwd, DialectHint: actionfacts.DialectPOSIX}
	request := shadowLiveRequest(command)
	request.Connector, request.Input, request.LegacyText = "claudecode", input, command
	request.targetMemo = hookpaths.NewTargetMemo()
	if !trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) {
		t.Fatal("the existing link into authorized_keys lost its block")
	}
}
