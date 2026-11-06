// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"archive/tar"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func gx054Verdict(t *testing.T, f b36ManagedHookFixture, connector, pack string, payload []byte, header string, managedCell bool) string {
	t.Helper()
	if managedCell {
		if err := os.Chmod(f.homes, 0); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(f.homes, 0o700)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePack = pack
	cfg.DataDir = os.Getenv("DEFENSECLAW_HOME")
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, header)
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managedCell {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
	}
	rec := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, `"deny"`) || strings.Contains(body, `"block"`) {
		if strings.Contains(body, "Archive extraction may create a link") {
			return "archive"
		}
		if strings.Contains(body, "SSH authorized keys mutation") {
			return "protected"
		}
		return "blocked"
	}
	return "allow"
}

// Keep the home short so its repeated path evidence stays below the bounded
// managed hook header, independently of the descriptive subtest name.
func gx054Fixture(t *testing.T) b36ManagedHookFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "gx-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	f := b36ManagedHookFixture{homes: filepath.Join(root, "homes")}
	f.home = filepath.Join(f.homes, "alice")
	f.project = filepath.Join(f.home, "project")
	f.keys = filepath.Join(f.home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(f.keys), f.project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(f.project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", f.home)
	t.Cleanup(func() { _ = os.Chmod(f.homes, 0o700) })
	return f
}

func TestGX054ArchiveScopeFourCell(t *testing.T) {
	rows := []struct {
		name, command                                    string
		balanced, strict, managedBalanced, managedStrict string
	}{
		{"plain tar move", "tar -xzf pkg.tgz -C app && mv app/pkg-1.0 app/pkg", "allow", "allow", "allow", "allow"},
		{"missing tar move with dotted name", "tar -xzf missing.tgz -C app && mv app/pkg-1.0 app/pkg", "allow", "archive", "allow", "allow"},
		{"missing tar move chain", "tar -xzf missing.tgz -C app && mv app/pkg-1.0 app/tmp && mv app/tmp app/pkg", "allow", "archive", "allow", "allow"},
		{"same command download", "wget -O pkg.tgz https://example.com/pkg.tgz && tar -xzf pkg.tgz -C app && mv app/pkg-1.0 app/pkg", "allow", "archive", "allow", "allow"},
		{"missing tar recursive copy", "tar -xzf missing.tgz -C app && cp -r app/pkg-1.0 app/pkg", "allow", "archive", "allow", "archive"},
		{"changed directory move", "cd app && tar -xzf ../missing.tgz && mv pkg-1.0 pkg", "allow", "archive", "allow", "archive"},
		{"zip recursive copy", "unzip -q pkg.zip -d app && cp -r app/pkg-1.0 app/pkg", "allow", "archive", "allow", "archive"},
		{"zip move", "unzip -q pkg.zip -d app && mv app/pkg-1.0 app/pkg", "allow", "archive", "allow", "allow"},
		{"seven zip copy", "7z x pkg.7z -oapp && cp -r app/pkg-1.0 app/pkg", "allow", "archive", "allow", "archive"},
		{"ditto copy", "unzip -q pkg.zip -d app && ditto app/pkg-1.0 app/pkg && echo k >> app/pkg/a.c", "allow", "archive", "allow", "archive"},
		{"cpio copy", "cpio -id -D app < pkg.cpio && cp -r app/pkg-1.0 app/pkg", "allow", "archive", "allow", "archive"},
		{"install from extraction", "tar -xzf missing.tgz -C app && install app/pkg-1.0/a.c app/out.c", "allow", "archive", "allow", "allow"},
		{"redirect into extraction", "tar -xzf missing.tgz -C app && echo k >> app/pkg-1.0/a.c", "allow", "archive", "allow", "archive"},
		{"in place edit", "tar -xzf missing.tgz -C app && sed -i s/x/y/ app/pkg-1.0/a.c", "allow", "allow", "allow", "archive"},
		{"home spelling ordinary move", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/app/pkg-1.0 ~/project/app/pkg", "allow", "allow", "protected", "protected"},
		{"plain tar managed copy", "tar -xzf pkg.tgz -C app && cp -r app/pkg-1.0 app/pkg", "allow", "allow", "allow", "archive"},
		{"plain tar copied append", "tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k >> e3/p", "allow", "allow", "allow", "archive"},
		{"plain tar synchronized append", "tar -xf plain.tar -C d1 && rsync -a d1/ e2/ && echo k >> e2/p", "allow", "allow", "allow", "archive"},
		{"link tar copied append", "tar -xf link.tar -C d1 && cp -a d1 e3 && echo k >> e3/p", "archive", "archive", "archive", "archive"},
		{"named protected destination", "tar -xzf missing.tgz -C app && mv app/pkg-1.0 ~/.ssh/authorized_keys", "protected", "protected", "protected", "protected"},
		{"named protected source", "unzip -q pkg.zip -d app && mv app/authorized_keys app/out", "protected", "protected", "protected", "protected"},
		{"known protected source value", "F=app/authorized_keys; unzip -q pkg.zip -d app && mv \"$F\" app/out", "protected", "protected", "protected", "protected"},
		{"known protected destination value", "D=app/authorized_keys; unzip -q pkg.zip -d app && mv app/pkg-1.0 \"$D\"", "protected", "protected", "protected", "protected"},
		{"known protected target value", "F=keylink; tar -xzf missing.tgz -C app && cp a.txt \"$F\"", "protected", "protected", "protected", "protected"},
		{"known protected link", "tar -xzf missing.tgz -C app && cp -r app/pkg-1.0 keylink", "protected", "protected", "protected", "protected"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := gx054Fixture(t)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			for _, dir := range []string{"app", "d1"} {
				if err := os.MkdirAll(filepath.Join(f.project, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			reg := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeReg} }
			r107WriteTar(t, filepath.Join(f.project, "pkg.tgz"), true, tar.Header{Name: "pkg-1.0/", Typeflag: tar.TypeDir}, reg("pkg-1.0/a.c"))
			r107WriteTar(t, filepath.Join(f.project, "plain.tar"), false, reg("p"))
			r107WriteTar(t, filepath.Join(f.project, "link.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys"})
			if err := os.WriteFile(filepath.Join(f.project, "pkg.zip"), append([]byte("PK\x05\x06"), make([]byte, 18)...), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if row.name == "in place edit" {
				if err := os.MkdirAll(filepath.Join(f.project, "app", "pkg-1.0"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.project, "app", "pkg-1.0", "a.c"), []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, connector := range []string{"claudecode", "codex"} {
				for _, cell := range []struct {
					pack    string
					managed bool
					want    string
				}{{"", false, row.balanced}, {"strict", false, row.strict}, {"", true, row.managedBalanced}, {"strict", true, row.managedStrict}} {
					os.Chmod(f.homes, 0o700)
					id := fmt.Sprintf("gx054-%s-%s-%t", row.name, cell.pack, cell.managed)
					payload := mustJSON(t, map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": id, "tool_input": map[string]any{"command": row.command, "description": "fixture"}})
					header := f.clientHeader(t, payload)
					got := gx054Verdict(t, f, connector, cell.pack, payload, header, cell.managed)
					if got != cell.want {
						t.Errorf("%s pack=%q managed=%t: got %s, want %s", connector, cell.pack, cell.managed, got, cell.want)
					}
				}
			}
		})
	}
}

func TestGX054OpenCodePatchNamesFourCell(t *testing.T) {
	for _, tool := range []string{"patch", "apply_patch"} {
		t.Run(tool, func(t *testing.T) {
			f := gx054Fixture(t)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			if err := os.WriteFile(filepath.Join(f.project, "existing.txt"), []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, row := range []struct{ name, patch, want string }{
				{"add new file", "*** Begin Patch\n*** Add File: notes.txt\n+note\n*** End Patch", "allow"},
				{"add new subdirectory", "*** Begin Patch\n*** Add File: sub/notes.txt\n+note\n*** End Patch", "allow"},
				{"update existing file", "*** Begin Patch\n*** Update File: existing.txt\n@@\n-old\n+new\n*** End Patch", "allow"},
				{"add protected file", "*** Begin Patch\n*** Add File: " + f.keys + "\n+note\n*** End Patch", "protected"},
				{"add linked file", "*** Begin Patch\n*** Add File: keylink\n+note\n*** End Patch", "protected"},
			} {
				t.Run(row.name, func(t *testing.T) {
					for _, pack := range []string{"", "strict"} {
						id := fmt.Sprintf("gx054-patch-%s-%s-%s", tool, row.name, pack)
						payload := mustJSON(t, map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": map[string]any{"patchText": row.patch}, "session_id": id, "turn_id": "m1", "tool_call_id": id, "agent_name": "build", "cwd": f.project, "arguments_authoritative": true, "mcp_identity_status": "not_mcp"})
						os.Chmod(f.homes, 0o700)
						header := hookpaths.ResolveConnector("opencode", "", "tool.execute.before", payload)
						facts, ok := hookpaths.Decode(header)
						if !ok || facts[hookpaths.PatchCompleteKey] != "1" {
							t.Errorf("client did not describe complete patch: %v", facts)
						}
						got := gx054Verdict(t, f, "opencode", pack, payload, header, true)
						if got != row.want {
							t.Errorf("pack=%q: got %s, want %s", pack, got, row.want)
						}
					}
				})
			}
		})
	}
}

// Every ordinary balanced expectation moved from the earlier extraction
// suites keeps a strict cell. This guards the tier boundary directly.
func TestGX054PinnedArchiveMovesRemainStrict(t *testing.T) {
	rows := []struct {
		name, command string
		perUser       bool
	}{
		{"extract redirect", `tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, true},
		{"extract redirect after cd", `cd {P} && tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, true},
		{"extract redirect after mkdir and cd", `cd {P} && mkdir -p unpack && tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, true},
		{"copy archive directory", `tar -xf keys.tar -C d0 && cp -a d0 e0 && echo k >> e0/k`, true},
		{"copy into target directory", `tar -xf keys.tar -C d0 && cp -a -t e1 d0 && echo k >> e1/d0/k`, true},
		{"recursive copy archive directory", `tar -xf keys.tar -C d0 && cp -r d0 e3 && echo k >> e3/k`, true},
		{"synchronize archive directory", `tar -xf keys.tar -C d0 && rsync -a d0/ e2/ && echo k >> e2/k`, true},
		{"copy of copy", `tar -xf keys.tar -C d0 && cp -a d0 e0 && cp -a e0 f0 && echo k >> f0/k`, true},
		{"rename into nested scope", `tar -C {P}/x -xzf {P}/journey1.tgz && mv {P}/x/journey1 {P}/x/sub/journey1-x`, true},
		{"move from scope", `tar -C {P}/x -xzf keys.tar && mv {P}/x/d/notes {P}/x/notes-x`, true},
		{"move onto scope root", `tar -C {P}/x -xzf keys.tar && mv notes {P}/x`, true},
		{"failed move then write", `tar -C {P}/x -xzf keys.tar; mv nosuch {P}/x/k; echo k >> {P}/x/k`, true},
		{"no clobber then write", `tar -C {P}/x -xzf keys.tar && mv -n notes {P}/x/k && echo k >> {P}/x/k`, true},
		{"write then move", `tar -C {P}/x -xzf keys.tar; echo k >> {P}/x/k; mv notes {P}/x/k`, true},
		{"copy then move", `tar -C {P}/x -xzf keys.tar; cp a.txt {P}/x/k; mv notes {P}/x/k`, true},
		{"managed plain copy append", `tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, false},
		{"managed plain sync append", `tar -xf plain.tar -C d1 && rsync -a d1/ e2/ && echo k >> e2/p`, false},
		{"managed plain append", `tar -xf plain.tar -C d1 && echo k >> d1/p`, false},
		{"managed plain tgz append", `tar -xzf plain.tgz -C d1 && cp -a d1 e3 && echo k >> e3/p`, false},
		{"archive rewritten", `cp link.tar plain.tar; tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k >> e3/p`, true},
		{"archive rewritten via alias", `cp link.tar alias.tar; tar -xf plain.tar -C d1 && echo k >> d1/p`, true},
		{"two archive words", `tar -xf plain.tar --file=plain.tgz -C d1 && echo k >> d1/p`, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := gx054Fixture(t)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			for _, name := range []string{"unpack", "d0", "d1", "x", "e1"} {
				if err := os.MkdirAll(filepath.Join(f.project, name), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"notes", "a.txt"} {
				if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(f.project, "journey1.tgz"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			reg := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeReg} }
			r107WriteTar(t, filepath.Join(f.project, "plain.tar"), false, reg("p"))
			r107WriteTar(t, filepath.Join(f.project, "plain.tgz"), true, reg("p"))
			r107WriteTar(t, filepath.Join(f.project, "link.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys"})
			if err := os.Link(filepath.Join(f.project, "plain.tar"), filepath.Join(f.project, "alias.tar")); err != nil {
				t.Fatal(err)
			}
			command := strings.ReplaceAll(row.command, "{P}", f.project)
			for _, connector := range []string{"claudecode", "codex"} {
				for _, managed := range []bool{false, true} {
					id := fmt.Sprintf("gx054-strict-%s-%s-%t", row.name, connector, managed)
					payload := mustJSON(t, map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": id, "tool_input": map[string]any{"command": command, "description": "fixture"}})
					os.Chmod(f.homes, 0o700)
					header := f.clientHeader(t, payload)
					got := gx054Verdict(t, f, connector, "strict", payload, header, managed)
					wantBlock := managed || row.perUser
					if (got != "allow") != wantBlock {
						t.Errorf("%s managed=%t: got %s, wantBlock=%t", connector, managed, got, wantBlock)
					}
				}
			}
		})
	}
}
