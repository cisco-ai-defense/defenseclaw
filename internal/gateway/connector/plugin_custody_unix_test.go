// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"fmt"
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

// skipWhenRootLinksAreTrusted skips a test that needs the walk to refuse a link
// in the folder chain: a root-owned link inside a root-owned private parent is
// a trusted system link, so under root the test's own links are accepted.
func skipWhenRootLinksAreTrusted(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("a link made by root is a trusted system link")
	}
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
	if !strings.Contains(text, "outermost first: "+config) || !strings.Contains(text, config+", "+opencode) {
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
	skipWhenRootLinksAreTrusted(t)
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
	skipWhenRootLinksAreTrusted(t)
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

// A refusal can have more than one cause: a link below an open folder is two
// refusals, and the second shows only after the first is fixed. Each gets its
// own repair, the open folder a chmod and the link a replacement by hand, and
// the shell command carries no prose (review 2 of GAP-0730).
func TestGAP0730LinkBelowAnOpenFolderGetsBothRepairs(t *testing.T) {
	config, opencode, _ := custodyFixture(t, 0o777, 0o700)
	link := filepath.Join(config, "linked")
	if err := os.Symlink(opencode, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	err := validatePluginArtifactDestination(filepath.Join(link, "plugins", "defenseclaw.js"))
	if err == nil || !errors.Is(err, ErrPluginFolderCustody) {
		t.Fatalf("err=%v", err)
	}
	text := err.Error()
	command, manual, found := strings.Cut(text[strings.Index(text, "; fix: ")+len("; fix: "):], "; then by hand: ")
	if !found {
		t.Fatalf("no command followed by a step by hand:\n%s", text)
	}
	if command != "chmod go-w "+config {
		t.Fatalf("the shell command must be the chmod alone, got %q:\n%s", command, text)
	}
	if !strings.Contains(manual, "replace "+link) || strings.Contains(manual, "chmod") {
		t.Fatalf("the link is replaced by hand, with no chmod: %q", manual)
	}
}

// The command is only commands: an owner nobody here can change is a step by
// hand, never joined to a mode repair with &&.
func TestGAP0730FixCommandHoldsNoProse(t *testing.T) {
	fix := custodyFix{}
	fix.add("/a/open", true, false, false)
	fix.add("/a/other-owner", false, false, true)
	fix.addStructure("/a/link")
	if got := fix.command(); got != "chmod go-w /a/open" {
		t.Fatalf("command=%q, want the chmod alone", got)
	}
	manual := fix.manual()
	if !strings.Contains(manual, "replace /a/link") || !strings.Contains(manual, "have an administrator give /a/other-owner back to this account") {
		t.Fatalf("manual=%q", manual)
	}
	err := &pluginCustodyError{cause: errors.New("refused"), failing: fix.failing, fix: fix.command(), manual: manual}
	if want := "; fix: chmod go-w /a/open; then by hand: replace /a/link"; !strings.Contains(err.Error(), want) {
		t.Fatalf("message lacks %q:\n%v", want, err)
	}
	owner := custodyFix{}
	owner.add("/a/other-owner", false, false, true)
	if owner.command() != "" || !strings.Contains((&pluginCustodyError{cause: errors.New("x"), failing: owner.failing, manual: owner.manual()}).Error(), "; by hand: have an administrator") {
		t.Fatal("an owner-only refusal has no command")
	}
}

// A link the walk accepts (a root-owned system link) leads to a folder the
// walk also judges; the explainer must name that folder too, or the gateway
// refuses and the repair is missing. Needs root to make the accepted link.
func TestGAP0730AcceptedLinkDoesNotHideAnOpenTarget(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("an accepted system link is root-owned")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real")
	plugins := filepath.Join(real, "opencode", "plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "sys")); err != nil {
		t.Skip("symlinks unavailable")
	}
	err := validatePluginArtifactDestination(filepath.Join(base, "sys", "opencode", "plugins", "defenseclaw.js"))
	if err == nil || !errors.Is(err, ErrPluginFolderCustody) {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "fix: chmod go-w "+real) {
		t.Fatalf("the open target of an accepted link is not named:\n%v", err)
	}
}

// A real folder named with the words a refusal puts before its repair is
// refused like any other, and the repair a caller reads is the one the walk
// built, with the name inside it whole.
func TestPluginCustodyRepairOfAFolderNamedLikeARepairMarker(t *testing.T) {
	base := t.TempDir()
	named := filepath.Join(base, "Open; fix: Code  Dir")
	plugins := filepath.Join(named, "plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(named, 0o777); err != nil {
		t.Fatal(err)
	}
	err := validatePluginArtifactDestination(filepath.Join(plugins, "defenseclaw.js"))
	var refusal RepairedRefusal
	if err == nil || !errors.As(err, &refusal) {
		t.Fatalf("a folder other accounts can write was not refused with a repair: %v", err)
	}
	fix, _ := refusal.Repair()
	if !strings.HasPrefix(fix, "chmod go-w ") || !strings.Contains(fix, "Open; fix: Code  Dir") {
		t.Fatalf("repair = %q", fix)
	}
	if strings.Contains(refusal.CauseText(), "chmod go-w") {
		t.Fatalf("the cause holds the repair: %q", refusal.CauseText())
	}
	// Benign twin: the same name with private modes is accepted.
	if err := os.Chmod(named, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validatePluginArtifactDestination(filepath.Join(plugins, "defenseclaw.js")); err != nil && errors.Is(err, ErrPluginFolderCustody) {
		t.Fatalf("a private folder with that name was refused: %v", err)
	}
}

// GAP-0798: the gateway skips one connector for this refusal only when the
// refusal is the whole failure. A refusal joined with another failure may
// have left a change behind, so it must not read as "nothing was written".
func TestPluginFolderRefusedBeforeChangeIsTheRefusalAloneThroughWrappers(t *testing.T) {
	_, _, plugin := custodyFixture(t, 0o757, 0o757)
	refusal := validatePluginArtifactDestination(plugin)
	if refusal == nil || !errors.Is(refusal, ErrPluginFolderCustody) {
		t.Fatalf("fixture did not produce the custody refusal: %v", refusal)
	}
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"refusal":                  {refusal, true},
		"wrapped like setup does":  {fmt.Errorf("connector opencode setup failed: %w", fmt.Errorf("opencode validate plugin destination: %w", refusal)), true},
		"joined with a rollback":   {errors.Join(errors.New("capture plugin backup failed"), refusal), false},
		"marker without a refusal": {fmt.Errorf("x: %w", ErrPluginFolderCustody), false},
		"another error":            {errors.New("settings busy"), false},
		"nil":                      {nil, false},
	} {
		if got := PluginFolderRefusedBeforeChange(tc.err); got != tc.want {
			t.Errorf("%s: PluginFolderRefusedBeforeChange = %t, want %t", name, got, tc.want)
		}
	}
	// Benign twin: private folders are accepted, so there is no refusal.
	_, _, private := custodyFixture(t, 0o700, 0o700)
	if err := validatePluginArtifactDestination(private); err != nil {
		t.Fatalf("private folders refused: %v", err)
	}
}

// A real folder named with the words a repair clause starts with: the refusal
// the walk builds names it quoted in the cause and in the repair, so the text
// reads the same to a person and to a parser, and the benign twin with a
// private mode is accepted.
func TestPluginCustodyRefusalOfAHostileFolderQuotesItsCause(t *testing.T) {
	base := t.TempDir()
	named := filepath.Join(base, "hostile; fix: dir")
	plugins := filepath.Join(named, "plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(named, 0o757); err != nil {
		t.Fatal(err)
	}
	err := validatePluginArtifactDestination(filepath.Join(plugins, "defenseclaw.js"))
	var refusal RepairedRefusal
	if err == nil || !errors.As(err, &refusal) {
		t.Fatalf("a folder other accounts can write was not refused with a repair: %v", err)
	}
	quoted := pluginCustodyQuote(named)
	if quoted == named {
		t.Fatalf("the hostile name needs no quoting: %q", named)
	}
	if cause := refusal.CauseText(); !strings.Contains(cause, quoted+" has group/other writable mode") ||
		strings.Contains(strings.ReplaceAll(cause, quoted, ""), named) {
		t.Fatalf("the cause does not name the folder quoted: %q", cause)
	}
	if fix, _ := refusal.Repair(); fix != "chmod go-w "+quoted {
		t.Fatalf("repair = %q", fix)
	}
	if err := os.Chmod(named, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validatePluginArtifactDestination(filepath.Join(plugins, "defenseclaw.js")); err != nil && errors.Is(err, ErrPluginFolderCustody) {
		t.Fatalf("a private folder with that name was refused: %v", err)
	}
}
