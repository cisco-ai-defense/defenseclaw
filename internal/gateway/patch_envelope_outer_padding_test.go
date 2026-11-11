// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// outerPaddedPatchCall is the typed Codex apply_patch call that adds one
// file with the given envelope spelling: wrap turns the plain patch text
// (ending in a line end) into the padded form the tool still applies.
func outerPaddedPatchCall(target, line string, wrap func(string) string) nativeWriteCall {
	return nativeWriteCall{"codex", "apply_patch", func(string) map[string]any {
		return map[string]any{"command": wrap("*** Begin Patch\n*** Add File: " + target + "\n+" + line + "\n*** End Patch\n")}
	}}
}

func paddedPatchVerdict(t *testing.T, pack, home, body string) string {
	t.Helper()
	return overLimitHostHookInPack(t, "codex", pack, home, body,
		hookpaths.ResolveConnector("codex", "", "preToolUse", []byte(body)))
}

// paddedPatchSpelling is one padded form of a plain apply_patch envelope.
type paddedPatchSpelling struct {
	name string
	wrap func(string) string
}

// TestPatchEnvelopePaddedOutsideKeepsContentRuleVerdict pins that a typed
// apply_patch envelope with white space around it, CRLF line ends or white
// space around a file header gets the verdict of the same envelope without it
// in the default and the strict tier: the patch tool trims the text before it
// reads the markers, so the padded text is a patch it applies. The same
// spellings of a benign file stay allowed. The small spellings run against
// every rule target in both tiers; a pad of tens of thousands of characters
// takes the same trim, so each size runs once, on one target, in one tier.
func TestPatchEnvelopePaddedOutsideKeepsContentRuleVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	link := filepath.Join(project, "lnk-preload")
	if err := os.Symlink("/etc/ld.so.preload", link); err != nil {
		t.Fatal(err)
	}
	type target struct{ name, path, attack, benign, rule string }
	preload := target{"ld.so.preload", "/etc/ld.so.preload", "/usr/local/lib/liblogger.so", "# no libraries are preloaded", "persistence.global_ld_preload_install"}
	check := func(t *testing.T, c target, pack string, spelling paddedPatchSpelling) {
		t.Parallel()
		body := outerPaddedPatchCall(c.path, c.attack, spelling.wrap).body(t, project, project)
		got := paddedPatchVerdict(t, pack, home, body)
		if overLimitHookAction(t, got) != "block" || !strings.Contains(got, c.rule) {
			t.Fatalf("not blocked by %s: %.600s", c.rule, got)
		}
		if strings.Contains(got, overLimitElidedContentTitle) {
			t.Fatalf("padding takes the conservative finding, not the rule verdict: %.600s", got)
		}
		benign := outerPaddedPatchCall(c.path, c.benign, spelling.wrap).body(t, project, project)
		if action := overLimitHookAction(t, paddedPatchVerdict(t, pack, home, benign)); action == "block" {
			t.Fatalf("benign text of %s blocked", c.path)
		}
	}
	small := []paddedPatchSpelling{
		{"plain", func(s string) string { return s }},
		{"no closing line end", func(s string) string { return strings.TrimSuffix(s, "\n") }},
		{"one trailing space", func(s string) string { return s + " " }},
		{"trailing tab", func(s string) string { return s + "\t" }},
		{"1000 trailing spaces", func(s string) string { return s + strings.Repeat(" ", 1000) }},
		{"extra newlines", func(s string) string { return s + "\n\n" }},
		{"one leading space", func(s string) string { return " " + s }},
		{"CRLF", func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }},
		{"CRLF and trailing spaces", func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") + "  \r\n" }},
		{"header trailing space", func(s string) string { return strings.Replace(s, "\n+", "  \n+", 1) }},
		{"header leading tab", func(s string) string { return strings.Replace(s, "*** Add", "\t*** Add", 1) }},
	}
	for _, c := range []target{
		preload,
		{"link to ld.so.preload", link, preload.attack, preload.benign, preload.rule},
		{"profile.d", "/etc/profile.d/logger.sh", "export LD_PRELOAD=/usr/local/lib/liblogger.so", "export CLICOLOR=1", "persistence.global_ld_preload_install"},
		{"daemon.json", "/etc/docker/daemon.json", overLimitDockerHTTPRegistry, `{"log-level":"warn"}`, dockerInsecureHTTPRegistryRuleID},
		{"pam.d", "/etc/pam.d/sshd", "auth sufficient pam_permit.so", "auth required pam_unix.so", "tamper.pam_permit_authentication_bypass"},
	} {
		for _, pack := range []string{"", "strict"} {
			for _, spelling := range small {
				t.Run(fmt.Sprintf("%s/%q/%s", c.name, pack, spelling.name), func(t *testing.T) {
					check(t, c, pack, spelling)
				})
			}
		}
	}
	for _, g := range []struct {
		pack     string
		spelling paddedPatchSpelling
	}{
		{"", paddedPatchSpelling{"300000 trailing spaces", func(s string) string { return s + strings.Repeat(" ", 300000) }}},
		{"strict", paddedPatchSpelling{"65536 trailing tabs", func(s string) string { return s + strings.Repeat("\t", 65536) }}},
		{"strict", paddedPatchSpelling{"300000 leading spaces", func(s string) string { return strings.Repeat(" ", 300000) + s }}},
	} {
		t.Run(fmt.Sprintf("%s/%q/%s", preload.name, g.pack, g.spelling.name), func(t *testing.T) {
			check(t, preload, g.pack, g.spelling)
		})
	}
}

// TestPatchEnvelopePaddedOrdinaryFileStaysAllowed is the benign twin: padded
// patches of ordinary files are not blocked in either tier, and one pad of
// 300000 characters runs once, in the default tier.
func TestPatchEnvelopePaddedOrdinaryFileStaysAllowed(t *testing.T) {
	home, project := hermesPatchHome(t)
	for _, c := range []struct {
		pack string
		paddedPatchSpelling
	}{
		{"", paddedPatchSpelling{"trailing space", func(s string) string { return s + " " }}},
		{"strict", paddedPatchSpelling{"trailing space", func(s string) string { return s + " " }}},
		{"", paddedPatchSpelling{"CRLF", func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }}},
		{"strict", paddedPatchSpelling{"CRLF", func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }}},
		{"", paddedPatchSpelling{"300000 spaces", func(s string) string { return s + strings.Repeat(" ", 300000) }}},
	} {
		t.Run(fmt.Sprintf("%q/%s", c.pack, c.name), func(t *testing.T) {
			t.Parallel()
			body := outerPaddedPatchCall(filepath.Join(project, "notes.txt"), "hello", c.wrap).body(t, project, project)
			got := paddedPatchVerdict(t, c.pack, home, body)
			if overLimitHookAction(t, got) == "block" {
				t.Fatalf("ordinary file blocked: %.600s", got)
			}
		})
	}
}
