// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// hostLinksEtc makes the test run as a host where /etc is a link to
// /private/etc (macOS) or as one where /private/etc is an ordinary directory.
func hostLinksEtc(t *testing.T, linked bool) {
	t.Helper()
	was := actionfacts.HostLinksEtcToPrivate
	actionfacts.HostLinksEtcToPrivate = linked
	t.Cleanup(func() { actionfacts.HostLinksEtcToPrivate = was })
}

// systemAliasEvidence rewrites the hook client evidence the way a macOS
// client writes it: /etc, /var and /tmp are links into /private, so the
// client lists each file under them with its physical name.
func systemAliasEvidence(t *testing.T, evidence string) string {
	t.Helper()
	hostLinksEtc(t, true)
	targets, ok := hookpaths.Decode(evidence)
	if !ok {
		t.Fatalf("hook evidence %q is not readable", evidence)
	}
	for operand, resolved := range targets {
		if operand != resolved {
			continue
		}
		for _, alias := range []string{"/etc/", "/var/", "/tmp/"} {
			if strings.HasPrefix(operand, alias) {
				targets[operand] = "/private" + resolved
			}
		}
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// TestFileToolOnASystemLinkKeepsItsContentRule pins GAP-0819: a whole-file
// write under a system path that is itself a link (/etc on macOS) keeps the
// verdict the same call gets where the path is its own file. The file the
// link reaches is one more spelling of the operand, so it does not break
// the exact proof of the content rule or read as an operand the client
// left out. Benign writes through the same links stay allowed.
func TestFileToolOnASystemLinkKeepsItsContentRule(t *testing.T) {
	home, project := hermesPatchHome(t)
	const preload = "# logger\nexport LD_PRELOAD=/usr/local/lib/liblogger.so\n"
	pad := strings.Repeat(" ", 70000)
	for _, c := range []struct {
		name, target, content, rule string
	}{
		{"docker insecure registry", "/etc/docker/daemon.json", overLimitDockerHTTPRegistry, dockerInsecureHTTPRegistryRuleID},
		{"docker insecure registry over the limit", "/etc/docker/daemon.json", overLimitDockerHTTPRegistry + pad, dockerInsecureHTTPRegistryRuleID},
		{"global preload", "/etc/profile.d/logger.sh", preload, "persistence.global_ld_preload_install"},
		{"benign daemon settings", "/etc/docker/daemon.json", `{"log-level":"warn"}`, ""},
		{"benign profile fragment", "/etc/profile.d/colors.sh", "export CLICOLOR=1\n", ""},
		{"project file", filepath.Join(project, "notes.txt"), preload, ""},
	} {
		for _, link := range []bool{false, true} {
			t.Run(c.name+"/link="+map[bool]string{false: "no", true: "yes"}[link], func(t *testing.T) {
				call := nativeWriteCall{"claudecode", "Write", func(path string) map[string]any {
					return map[string]any{"file_path": path, "content": c.content}
				}}
				body := call.body(t, project, c.target)
				evidence := hookpaths.ResolveConnector("claudecode", "", "preToolUse", []byte(body))
				if link {
					evidence = systemAliasEvidence(t, evidence)
				}
				got := overLimitHostHookWithEvidence(t, "claudecode", home, body, evidence)
				action := overLimitHookAction(t, got)
				if c.rule == "" {
					if action == "block" {
						t.Fatalf("benign write action = %q, want it not blocked: %.600s", action, got)
					}
					return
				}
				if action != "block" || !strings.Contains(got, c.rule) {
					t.Fatalf("action = %q, want block by %s: %.600s", action, c.rule, got)
				}
			})
		}
	}
}

// TestOverLimitPatchOnASystemLinkKeepsItsVerdict pins that a Codex patch
// padded past the argument limit keeps the verdict of the same patch at
// normal size when the client lists its file by the physical name of a
// system link (GAP-0819).
func TestOverLimitPatchOnASystemLinkKeepsItsVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	verdict := func(body string) string {
		call := nativeWriteCall{"codex", "apply_patch", func(string) map[string]any {
			return map[string]any{"command": "*** Begin Patch\n*** Add File: /etc/docker/daemon.json\n+" + body + "\n*** End Patch\n"}
		}}
		hook := call.body(t, project, "/etc/docker/daemon.json")
		evidence := systemAliasEvidence(t, hookpaths.ResolveConnector("codex", "", "preToolUse", []byte(hook)))
		return overLimitHookAction(t, overLimitHostHookWithEvidence(t, "codex", home, hook, evidence))
	}
	small := verdict(overLimitDockerHTTPRegistry)
	if padded := verdict(overLimitDockerHTTPRegistry + strings.Repeat(" ", 70000)); padded != small {
		t.Fatalf("padded verdict %q, small %q", padded, small)
	}
}

// TestFileToolOnThePhysicalSystemSpellingKeepsItsContentRule pins GAP-0819:
// a whole-file write that names a protected system file by its physical macOS
// spelling (/private/etc, where /etc is a link) gets the verdict the same
// write gets under /etc. The benign twins stay allowed under both spellings.
func TestFileToolOnThePhysicalSystemSpellingKeepsItsContentRule(t *testing.T) {
	home, project := hermesPatchHome(t)
	const preload = "# logger\nexport LD_PRELOAD=/usr/local/lib/liblogger.so\n"
	for _, c := range []struct {
		name, connector, tool, pathKey, target, content string
		blocked                                         bool
	}{
		{"docker insecure registry", "claudecode", "Write", "file_path", "/etc/docker/daemon.json", overLimitDockerHTTPRegistry, true},
		{"global preload fragment", "claudecode", "Write", "file_path", "/etc/profile.d/logger.sh", preload, true},
		{"benign daemon settings", "claudecode", "Write", "file_path", "/etc/docker/daemon.json", `{"log-level":"warn"}`, false},
		{"benign profile fragment", "claudecode", "Write", "file_path", "/etc/profile.d/colors.sh", "export CLICOLOR=1\n", false},
	} {
		for _, spelling := range []string{"/etc", "/private/etc"} {
			t.Run(c.name+"/"+spelling, func(t *testing.T) {
				hostLinksEtc(t, true)
				target := spelling + strings.TrimPrefix(c.target, "/etc")
				call := nativeWriteCall{c.connector, c.tool, func(path string) map[string]any {
					return map[string]any{c.pathKey: path, "content": c.content}
				}}
				body := call.body(t, project, target)
				evidence := hookpaths.ResolveConnector(c.connector, "", "preToolUse", []byte(body))
				action := overLimitHookAction(t, overLimitHostHookWithEvidence(t, c.connector, home, body, evidence))
				if c.blocked != (action == "block") {
					t.Fatalf("%s: action = %q, want blocked=%v", target, action, c.blocked)
				}
			})
		}
	}
}

// TestPAMConfigWriteOnThePhysicalSystemSpellingKeepsItsContentRule pins
// GAP-0819: the PAM grammar of the single /etc/pam.conf file is chosen for its
// physical macOS spelling too, so a permit auth line written whole or inserted
// by a literal edit is judged under both spellings. The service-directory
// files and the benign twins keep their verdicts.
func TestPAMConfigWriteOnThePhysicalSystemSpellingKeepsItsContentRule(t *testing.T) {
	home, project := hermesPatchHome(t)
	write := func(content string) func(string) map[string]any {
		return func(path string) map[string]any { return map[string]any{"file_path": path, "content": content} }
	}
	edit := func(oldText, newText string) func(string) map[string]any {
		return func(path string) map[string]any {
			return map[string]any{"file_path": path, "old_string": oldText, "new_string": newText, "replace_all": true}
		}
	}
	for _, c := range []struct {
		name, tool, target string
		args               func(string) map[string]any
		blocked            bool
	}{
		{"pam.conf full write", "Write", "/etc/pam.conf", write("login auth sufficient pam_permit.so\n"), true},
		{"pam.conf literal edit", "Edit", "/etc/pam.conf", edit("login auth required pam_deny.so", "login auth required pam_deny.so\nlogin auth sufficient pam_permit.so"), true},
		{"service file full write", "Write", "/etc/pam.d/sshd", write("auth sufficient pam_permit.so\n"), true},
		{"benign pam.conf write", "Write", "/etc/pam.conf", write("login auth required pam_unix.so\n"), false},
		{"benign service file write", "Write", "/etc/pam.d/sshd", write("auth required pam_unix.so\n"), false},
	} {
		for _, spelling := range []string{"/etc", "/private/etc"} {
			t.Run(c.name+"/"+spelling, func(t *testing.T) {
				hostLinksEtc(t, true)
				target := spelling + strings.TrimPrefix(c.target, "/etc")
				call := nativeWriteCall{"claudecode", c.tool, c.args}
				body := call.body(t, project, target)
				evidence := hookpaths.ResolveConnector("claudecode", "", "preToolUse", []byte(body))
				action := overLimitHookAction(t, overLimitHostHookWithEvidence(t, "claudecode", home, body, evidence))
				if c.blocked != (action == "block") {
					t.Fatalf("%s: action = %q, want blocked=%v", target, action, c.blocked)
				}
			})
		}
	}
}

// TestPhysicalEtcSpellingIsAnOrdinaryPathWhereEtcIsNotALink pins that the
// macOS alias is not applied elsewhere: on a host where /private/etc is an
// ordinary directory, whole-file writes below it, including a long note, keep
// the allow they get at any other ordinary path (GAP-0819).
func TestPhysicalEtcSpellingIsAnOrdinaryPathWhereEtcIsNotALink(t *testing.T) {
	home, project := hermesPatchHome(t)
	hostLinksEtc(t, false)
	pad := strings.Repeat("# note\n", 12000)
	for _, c := range []struct{ name, target, content string }{
		{"daemon settings", "/private/etc/docker/daemon.json", `{"log-level":"warn"}`},
		{"long profile note", "/private/etc/profile.d/colors.sh", "export CLICOLOR=1\n" + pad},
		{"long daemon note", "/private/etc/docker/daemon.json", `{"log-level":"warn"}` + pad},
		{"pam.conf note", "/private/etc/pam.conf", "login auth required pam_unix.so\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			call := nativeWriteCall{"claudecode", "Write", func(path string) map[string]any {
				return map[string]any{"file_path": path, "content": c.content}
			}}
			body := call.body(t, project, c.target)
			evidence := hookpaths.ResolveConnector("claudecode", "", "preToolUse", []byte(body))
			if action := overLimitHookAction(t, overLimitHostHookWithEvidence(t, "claudecode", home, body, evidence)); action == "block" {
				t.Fatalf("%s: ordinary file blocked", c.target)
			}
		})
	}
}
