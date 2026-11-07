// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// custodyFixture is <base>/.config/opencode/plugins with the modes given.
func custodyFixture(t *testing.T, configMode, opencodeMode os.FileMode) (config, opencode, plugin string) {
	t.Helper()
	base := t.TempDir()
	config = filepath.Join(base, ".config")
	opencode = filepath.Join(config, "opencode")
	plugins := filepath.Join(opencode, "plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	for dir, mode := range map[string]os.FileMode{config: configMode, opencode: opencodeMode} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
	}
	return config, opencode, filepath.Join(plugins, "defenseclaw.js")
}

// GAP-0730: the walk checks the leaf first, so the refusal named the leaf
// while a folder above it was just as open and fixing the leaf did not clear
// it. Every refused folder is named, outermost first, with one command.
func TestGAP0730RefusalNamesEveryOpenFolderOutermostFirstWithOneCommand(t *testing.T) {
	config, opencode, plugin := custodyFixture(t, 0o757, 0o757)
	err := validatePluginArtifactDestination(plugin)
	if err == nil {
		t.Fatal("folders other accounts can write were accepted")
	}
	if !errors.Is(err, ErrPluginFolderCustody) {
		t.Fatalf("refusal does not carry the custody marker: %v", err)
	}
	text := err.Error()
	if want := "chmod go-w " + config + " " + opencode; !strings.Contains(text, want) {
		t.Fatalf("refusal lacks one command for both folders %q:\n%s", want, text)
	}
	if strings.Index(text, "outermost first: "+config) < 0 || strings.Index(text, config+", "+opencode) < 0 {
		t.Fatalf("refusal does not list the outer folder first:\n%s", text)
	}
	if !strings.Contains(text, opencode+" has group/other writable mode") {
		t.Fatalf("the original cause was dropped:\n%s", text)
	}
}

func TestGAP0730RefusalOfOnlyTheLeafNamesOnlyTheLeaf(t *testing.T) {
	config, opencode, plugin := custodyFixture(t, 0o755, 0o757)
	err := validatePluginArtifactDestination(plugin)
	if err == nil || !errors.Is(err, ErrPluginFolderCustody) {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "fix: chmod go-w "+opencode) || strings.Contains(err.Error(), config+" ") {
		t.Fatalf("refusal names the wrong folders:\n%v", err)
	}
}

// The plugin file is judged by the same custody rule as its folders.
func TestGAP0730RefusalNamesAPluginFileOthersCanWrite(t *testing.T) {
	_, _, plugin := custodyFixture(t, 0o755, 0o755)
	if err := os.WriteFile(plugin, []byte("// managed plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(plugin, 0o666); err != nil {
		t.Fatal(err)
	}
	err := validatePluginArtifactDestination(plugin)
	if err == nil || !errors.Is(err, ErrPluginFolderCustody) {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "fix: chmod go-w "+plugin) {
		t.Fatalf("refusal does not name the plugin file:\n%v", err)
	}
}

// Benign twin: private folders and a private plugin stay accepted, and a
// refusal that is not about permissions is given no chmod (a link in the chain
// is not fixed with one).
func TestGAP0730PrivateFoldersStayAcceptedAndOtherRefusalsKeepTheirText(t *testing.T) {
	_, opencode, plugin := custodyFixture(t, 0o755, 0o755)
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("private folders refused: %v", err)
	}
	if err := os.WriteFile(plugin, []byte("// managed plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("private plugin refused: %v", err)
	}
	link := filepath.Join(filepath.Dir(opencode), "linked")
	if err := os.Symlink(opencode, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	err := validatePluginArtifactDestination(filepath.Join(link, "plugins", "defenseclaw.js"))
	if err == nil {
		t.Fatal("a plugin folder reached through a link was accepted")
	}
	if strings.Contains(err.Error(), "chmod") || !strings.Contains(err.Error(), "replace "+link) {
		t.Fatalf("a link refusal was given a chmod fix or does not name the link: %v", err)
	}
}

// A link whose target is group/other writable is still a link refusal: the
// chmod that would clear the target does not clear the link, so no chmod is
// offered and the link is named (review 1 of GAP-0730). A link to a private
// target and a link to an open one are refused with the same advice.
func TestGAP0730LinkToAnOpenFolderIsNamedAndGetsNoChmod(t *testing.T) {
	for _, mode := range []os.FileMode{0o700, 0o777} {
		_, opencode, _ := custodyFixture(t, 0o755, mode)
		link := filepath.Join(filepath.Dir(opencode), "linked")
		if err := os.Symlink(opencode, link); err != nil {
			t.Skip("symlinks unavailable")
		}
		err := validatePluginArtifactDestination(filepath.Join(link, "plugins", "defenseclaw.js"))
		if err == nil {
			t.Fatalf("mode %o: a plugin folder reached through a link was accepted", mode)
		}
		if strings.Contains(err.Error(), "chmod") || !strings.Contains(err.Error(), "replace "+link) || !errors.Is(err, ErrPluginFolderCustody) {
			t.Fatalf("mode %o: a link refusal must name the link and no chmod:\n%v", mode, err)
		}
	}
}

// The plugin file itself as a link is structural too.
func TestGAP0730PluginFileThatIsALinkIsNamedAndGetsNoChmod(t *testing.T) {
	_, _, plugin := custodyFixture(t, 0o755, 0o755)
	target := filepath.Join(t.TempDir(), "elsewhere.js")
	if err := os.WriteFile(target, []byte("//\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, plugin); err != nil {
		t.Skip("symlinks unavailable")
	}
	err := validatePluginArtifactDestination(plugin)
	if err == nil || strings.Contains(err.Error(), "chmod") || !strings.Contains(err.Error(), "replace "+plugin) {
		t.Fatalf("err=%v", err)
	}
}

func TestGAP0730FixCommandQuotesPathsThatNeedIt(t *testing.T) {
	for in, want := range map[string]string{
		"/home/a/.config/opencode": "/home/a/.config/opencode",
		"/home/a b/.config":        "'/home/a b/.config'",
		"/home/it's/.config":       "'/home/it'\\''s/.config'",
	} {
		if got := pluginCustodyQuote(in); got != want {
			t.Fatalf("quote(%q)=%q, want %q", in, got, want)
		}
	}
}
