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
)

// betweenLimitsPatchCall is the typed Codex apply_patch call that adds target
// with the given text lines, each as a line of the file.
func betweenLimitsPatchCall(target string, lines ...string) nativeWriteCall {
	return nativeWriteCall{"codex", "apply_patch", func(string) map[string]any {
		var patch strings.Builder
		patch.WriteString("*** Begin Patch\n*** Add File: " + target + "\n")
		for _, line := range lines {
			patch.WriteString("+" + line + "\n")
		}
		patch.WriteString("*** End Patch\n")
		return map[string]any{"command": patch.String()}
	}}
}

// TestOverLimitPatchFillerLineKeepsContentRuleVerdict pins that a typed
// apply_patch envelope with a filler line of white space on a line of its own
// keeps the verdict of the same envelope without it, at every size: the
// loader-preload, profile.d, Docker and PAM content proofs read the protected
// line below 64 KiB, between 64 KiB and the argument limit, and above it,
// for the file and for a link to it. The same envelope with benign text stays
// allowed.
func TestOverLimitPatchFillerLineKeepsContentRuleVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	link := filepath.Join(project, "lnk-preload")
	if err := os.Symlink("/etc/ld.so.preload", link); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, target, attack, benign, rule string
	}{
		{"ld.so.preload", "/etc/ld.so.preload", "/usr/local/lib/liblogger.so", "# no libraries are preloaded", "persistence.global_ld_preload_install"},
		{"link to ld.so.preload", link, "/usr/local/lib/liblogger.so", "# no libraries are preloaded", "persistence.global_ld_preload_install"},
		{"profile.d", "/etc/profile.d/logger.sh", "export LD_PRELOAD=/usr/local/lib/liblogger.so", "export CLICOLOR=1", "persistence.global_ld_preload_install"},
		{"daemon.json", "/etc/docker/daemon.json", overLimitDockerHTTPRegistry, `{"log-level":"warn"}`, dockerInsecureHTTPRegistryRuleID},
		{"pam.d", "/etc/pam.d/sshd", "auth sufficient pam_permit.so", "auth required pam_unix.so", "tamper.pam_permit_authentication_bypass"},
	} {
		for _, filler := range []int{0, 65536, 100000, 200000, 262000, 270000, 300000} {
			for _, layout := range []string{"lead, filler, text", "filler, text", "text, filler"} {
				lines := func(text string) []string {
					pad := strings.Repeat(" ", filler)
					switch layout {
					case "filler, text":
						return []string{pad, text}
					case "text, filler":
						return []string{text, pad}
					}
					// A JSON document takes no comment line.
					if strings.HasSuffix(c.target, ".json") {
						return []string{"", pad, text}
					}
					return []string{"# c", pad, text}
				}
				t.Run(fmt.Sprintf("%s/filler %d/%s", c.name, filler, layout), func(t *testing.T) {
					got := overLimitPatchVerdict(t, home, project, betweenLimitsPatchCall(c.target, lines(c.attack)...))
					if overLimitHookAction(t, got) != "block" || !strings.Contains(got, c.rule) {
						t.Fatalf("not blocked by %s: %.600s", c.rule, got)
					}
					if strings.Contains(got, overLimitElidedContentTitle) {
						t.Fatalf("padding takes the conservative finding, not the rule verdict: %.600s", got)
					}
					if filler != 100000 && filler != 270000 {
						return
					}
					benign := overLimitPatchVerdict(t, home, project, betweenLimitsPatchCall(c.target, lines(c.benign)...))
					if overLimitHookAction(t, benign) == "block" {
						t.Fatalf("benign text of %s blocked: %.600s", c.target, benign)
					}
					ordinary := overLimitPatchVerdict(t, home, project,
						betweenLimitsPatchCall(filepath.Join(project, "notes.txt"), lines(c.attack)...))
					if overLimitHookAction(t, ordinary) == "block" {
						t.Fatalf("the same text in an ordinary file blocked: %.600s", ordinary)
					}
				})
			}
		}
	}
}

// TestOverLimitPatchTextBetweenLimitsFailsClosedForItsTargetOnly pins that a
// patch file whose text is over 64 KiB with no padding to remove, in an
// envelope within the argument limit, takes the conservative finding when a
// content rule decides on its file, as it does past the argument limit, and
// that no ordinary file, and no other file of the patch, does.
func TestOverLimitPatchTextBetweenLimitsFailsClosedForItsTargetOnly(t *testing.T) {
	home, project := hermesPatchHome(t)
	opaque := strings.Repeat("x", 100000)
	ordinary := filepath.Join(project, "big.txt")
	link := filepath.Join(project, "lnk-preload")
	if err := os.Symlink("/etc/ld.so.preload", link); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		changes [][2]string
		block   bool
		rule    string
	}{
		{"opaque ld.so.preload", [][2]string{{"/etc/ld.so.preload", opaque}}, true, "persistence.global_ld_preload_install"},
		{"opaque link to ld.so.preload", [][2]string{{link, opaque}}, true, "persistence.global_ld_preload_install"},
		{"opaque daemon.json", [][2]string{{"/etc/docker/daemon.json", opaque}}, true, dockerInsecureHTTPRegistryRuleID},
		{"opaque pam.d", [][2]string{{"/etc/pam.d/sshd", opaque}}, true, "tamper.pam_permit_authentication_bypass"},
		{"opaque ordinary file", [][2]string{{ordinary, opaque}}, false, ""},
		{"opaque ordinary beside benign daemon.json", [][2]string{{ordinary, opaque}, {"/etc/docker/daemon.json", `{"log-level":"warn"}`}}, false, ""},
		{"opaque ordinary beside attack daemon.json", [][2]string{{ordinary, opaque}, {"/etc/docker/daemon.json", overLimitDockerHTTPRegistry}}, true, dockerInsecureHTTPRegistryRuleID},
		{"opaque daemon.json beside ordinary", [][2]string{{"/etc/docker/daemon.json", opaque}, {filepath.Join(project, "a.txt"), "ok"}}, true, dockerInsecureHTTPRegistryRuleID},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := overLimitPatchVerdict(t, home, project, overLimitPatchCall(c.changes, 0, false))
			if (overLimitHookAction(t, got) == "block") != c.block {
				t.Fatalf("block = %t, want %t: %.600s", !c.block, c.block, got)
			}
			if c.block && !strings.Contains(got, c.rule) {
				t.Fatalf("block does not name %s: %.600s", c.rule, got)
			}
			if !c.block && strings.Contains(got, overLimitElidedContentTitle) {
				t.Fatalf("conservative finding on a call that needs none: %.600s", got)
			}
		})
	}
}
