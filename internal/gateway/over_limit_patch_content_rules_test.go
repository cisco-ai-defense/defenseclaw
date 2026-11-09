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

// overLimitPatchCall is the typed Codex apply_patch call that adds the files
// of changes ("path" -> one text line) with the line padded by pad spaces
// before or after it.
func overLimitPatchCall(changes [][2]string, pad int, leading bool) nativeWriteCall {
	return nativeWriteCall{"codex", "apply_patch", func(string) map[string]any {
		var patch strings.Builder
		patch.WriteString("*** Begin Patch\n")
		for _, change := range changes {
			text := change[1]
			if leading {
				text = strings.Repeat(" ", pad) + text
			} else {
				text += strings.Repeat(" ", pad)
			}
			patch.WriteString("*** Add File: " + change[0] + "\n+" + text + "\n")
		}
		patch.WriteString("*** End Patch\n")
		return map[string]any{"command": patch.String()}
	}}
}

func overLimitPatchVerdict(t *testing.T, home, project string, call nativeWriteCall) string {
	t.Helper()
	return overLimitHostHook(t, "codex", home, call.body(t, project, project))
}

// TestOverLimitPatchPaddingKeepsContentRuleVerdict pins that a typed
// apply_patch envelope padded past the argument limit keeps the verdict of
// the same envelope unpadded: the loader-preload, Docker and PAM content
// proofs read the protected line at every padding, before or after it, for
// the file and for a link to it. The same padding on benign text stays
// allowed.
func TestOverLimitPatchPaddingKeepsContentRuleVerdict(t *testing.T) {
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
		for _, pad := range []int{0, 250000, 300000, 1000000} {
			for _, leading := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/pad %d leading %t", c.name, pad, leading), func(t *testing.T) {
					got := overLimitPatchVerdict(t, home, project, overLimitPatchCall([][2]string{{c.target, c.attack}}, pad, leading))
					if overLimitHookAction(t, got) != "block" || !strings.Contains(got, c.rule) {
						t.Fatalf("not blocked by %s: %.600s", c.rule, got)
					}
					if strings.Contains(got, overLimitElidedContentTitle) {
						t.Fatalf("padding takes the conservative finding, not the rule verdict: %.600s", got)
					}
					if pad != 300000 {
						return
					}
					benign := overLimitPatchVerdict(t, home, project, overLimitPatchCall([][2]string{{c.target, c.benign}}, pad, leading))
					if action := overLimitHookAction(t, benign); action == "block" {
						t.Fatalf("benign text of %s blocked: %.600s", c.target, benign)
					}
				})
			}
		}
	}
}

// TestOverLimitPatchOpaqueTextFailsClosedForItsTargetOnly pins that a
// patch file whose text cannot be bounded (no white space padding to
// remove) takes the conservative finding when a content rule decides on
// its file, and that no other file of the patch, and no ordinary file, does.
func TestOverLimitPatchOpaqueTextFailsClosedForItsTargetOnly(t *testing.T) {
	home, project := hermesPatchHome(t)
	opaque := strings.Repeat("x", 300000)
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
		{"900 KB ordinary file", [][2]string{{ordinary, strings.Repeat("y", 900000)}}, false, ""},
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

// TestOverLimitWriteOpaqueTextToLinkFailsClosed pins that a Write whose text
// cannot be bounded takes the conservative finding when its target is a link
// to a file a content rule decides on, as it does for the file itself, and
// that the same text to a link to an ordinary file stays allowed.
func TestOverLimitWriteOpaqueTextToLinkFailsClosed(t *testing.T) {
	home, project := hermesPatchHome(t)
	preload, ordinary := filepath.Join(project, "lnk-preload"), filepath.Join(project, "lnk-notes")
	for link, target := range map[string]string{preload: "/etc/ld.so.preload", ordinary: filepath.Join(project, "notes.txt")} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	opaque := "# a\n" + strings.Repeat("x", 70000)
	for link, block := range map[string]bool{preload: true, ordinary: false} {
		call := nativeWriteCall{"claudecode", "Write", func(string) map[string]any {
			return map[string]any{"file_path": link, "content": opaque}
		}}
		got := overLimitHostHook(t, "claudecode", home, call.body(t, project, link))
		if (overLimitHookAction(t, got) == "block") != block {
			t.Fatalf("%s: block = %t, want %t: %.600s", link, !block, block, got)
		}
	}
}

// TestOverLimitPatchRelativeLinkKeepsContentRule pins that a patch file named
// by a relative link, which the hook client attests as the protected file it
// reaches, is judged as that file whether its text is white space padded or
// cannot be bounded, and that the same text through a relative link to an
// ordinary file stays allowed.
func TestOverLimitPatchRelativeLinkKeepsContentRule(t *testing.T) {
	home, project := hermesPatchHome(t)
	for name, target := range map[string]string{
		"lnk-preload": "/etc/ld.so.preload",
		"lnk-notes":   filepath.Join(project, "notes.txt"),
	} {
		if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	attack := "/usr/local/lib/libreview.so"
	for _, c := range []struct {
		name, link, content string
		block               bool
	}{
		{"padded attack", "lnk-preload", attack + strings.Repeat(" ", 300000), true},
		{"attack beside opaque text", "lnk-preload", attack + "\n+#" + strings.Repeat("x", 300000), true},
		{"opaque text", "lnk-preload", strings.Repeat("x", 300000), true},
		{"opaque text to an ordinary link", "lnk-notes", strings.Repeat("x", 300000), false},
		{"padded text to an ordinary link", "lnk-notes", "# ok" + strings.Repeat(" ", 300000), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := overLimitPatchCall([][2]string{{c.link, c.content}}, 0, false).body(t, project, project)
			evidence := hookpaths.ResolveConnector("codex", "", "preToolUse", []byte(body))
			if resolved, ok := hookpaths.Decode(evidence); !ok || resolved[filepath.Join(project, c.link)] == "" {
				t.Fatal("hook client did not attest the relative link target")
			}
			got := overLimitHostHookWithEvidence(t, "codex", home, body, evidence)
			if (overLimitHookAction(t, got) == "block") != c.block {
				t.Fatalf("block = %t, want %t: %.600s", !c.block, c.block, got)
			}
			if c.block && !strings.Contains(got, "persistence.global_ld_preload_install") {
				t.Fatalf("block does not name the preload rule: %.600s", got)
			}
		})
	}
}
