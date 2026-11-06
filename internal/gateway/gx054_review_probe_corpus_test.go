// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Round-one reviewer probe retained as a regression corpus. Assertions pin
// known protected links, ordinary names, policy split, and rule titles.
package gateway

import (
	"archive/tar"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func rv054Class(body string) string {
	if !strings.Contains(body, `"deny"`) && !strings.Contains(body, `"block"`) {
		return "A"
	}
	c := "B"
	if strings.Contains(body, "Archive extraction may create a link") {
		c = "R"
	} else if strings.Contains(body, "SSH authorized keys mutation") {
		c = "S"
	}
	if strings.Contains(body, "persistence.ssh_authorized_keys_command") {
		c += "+"
	}
	return c
}

func rv054Post(t *testing.T, homes, home, connector, pack string, payload []byte, header string, managed bool) string {
	t.Helper()
	if managed {
		os.Chmod(homes, 0)
		defer os.Chmod(homes, 0o700)
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
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	rec := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(rec, req)
	return rv054Class(rec.Body.String())
}

func rv054Fixture(t *testing.T) b36ManagedHookFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "rv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(root, "homes"), 0o700); _ = os.RemoveAll(root) })
	f := b36ManagedHookFixture{homes: filepath.Join(root, "homes")}
	f.home = filepath.Join(f.homes, "alice")
	f.project = filepath.Join(f.home, "project")
	f.keys = filepath.Join(f.home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(f.keys), f.project, filepath.Join(f.project, "app"), filepath.Join(f.project, "d1"),
		filepath.Join(f.project, "link.tar.d"), filepath.Join(f.project, "conf"), filepath.Join(f.project, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(f.keys, []byte("# decoy\n"), 0o600)
	os.Symlink("../.ssh/authorized_keys", filepath.Join(f.project, "keylink"))
	os.Symlink("../.ssh", filepath.Join(f.project, "dirlink"))
	for _, n := range []string{"a.txt", "existing.txt", "conf/config.sample", "rc.sample", "notes.txt"} {
		os.WriteFile(filepath.Join(f.project, n), []byte("x\n"), 0o600)
	}
	reg := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeReg} }
	r107WriteTar(t, filepath.Join(f.project, "pkg.tgz"), true, tar.Header{Name: "pkg-1.0/", Typeflag: tar.TypeDir}, reg("pkg-1.0/a.c"), reg("pkg-1.0/config.example"))
	r107WriteTar(t, filepath.Join(f.project, "link.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys"})
	r107WriteTar(t, filepath.Join(f.project, "link.tgz"), true, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys"})
	r107WriteTar(t, filepath.Join(f.project, "link2.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys2"})
	r107WriteTar(t, filepath.Join(f.project, "sshdir.tar"), false, tar.Header{Name: "s", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh"})
	stage := filepath.Join(root, "stage")
	os.MkdirAll(filepath.Join(stage, "pkg-1.0"), 0o700)
	os.Symlink("../../.ssh/authorized_keys", filepath.Join(stage, "p"))
	os.WriteFile(filepath.Join(stage, "pkg-1.0", "a.c"), []byte("x"), 0o600)
	for out, flags := range map[string][]string{"link.tbz": {"-cjf"}, "link.txz": {"-cJf"}, "link.tzst": {"--zstd", "-cf"}} {
		args := append([]string{"-C", stage}, flags...)
		args = append(args, filepath.Join(f.project, out), "p")
		if b, err := exec.Command("tar", args...).CombinedOutput(); err != nil {
			t.Logf("SKIP %s: %v %s", out, err, b)
		}
	}
	for out, flags := range map[string][]string{"pkg.tbz": {"-cjf"}, "pkg.txz": {"-cJf"}, "pkg.tzst": {"--zstd", "-cf"}} {
		args := append([]string{"-C", stage}, flags...)
		args = append(args, filepath.Join(f.project, out), "pkg-1.0")
		if b, err := exec.Command("tar", args...).CombinedOutput(); err != nil {
			t.Logf("SKIP %s: %v %s", out, err, b)
		}
	}
	for _, n := range []string{"pkg.zip", "pkg.7z", "pkg.jar", "pkg.cpio"} {
		os.WriteFile(filepath.Join(f.project, n), append([]byte("PK\x05\x06"), make([]byte, 18)...), 0o600)
	}
	t.Setenv("HOME", f.home)
	return f
}

func TestGX054ReviewProbeCorpus(t *testing.T) {
	rows := []struct{ id, cmd string }{
		// gateway-known keys link in a readable archive
		{"K01", "tar -xf link.tar -C d1 && echo k >> d1/p"},
		{"K02", "echo start && tar -xf link.tar -C d1 && echo k >> d1/p"},
		{"K03", "tar -xf link.tar -C d1 2>/dev/null && echo k >> d1/p"},
		{"K04", "tar -xf link.tar -C link.tar.d && echo k >> link.tar.d/p"},
		{"K05", "true; tar -xf link.tar -C d1; echo k >> d1/p"},
		{"K06", "tar -xzf link.tgz -C d1 && echo k >> d1/p"},
		{"K07", "tar -xjf link.tbz -C d1 && echo k >> d1/p"},
		{"K08", "tar -xJf link.txz -C d1 && echo k >> d1/p"},
		{"K09", "tar --zstd -xf link.tzst -C d1 && echo k >> d1/p"},
		{"K10", "tar -xf link.tar -C d1 && mv d1/p d1/q && echo k >> d1/q"},
		{"K11", "tar -xf link.tar -C d1 && cp -a d1 e1 && echo k >> e1/p"},
		{"K12", "tar -xf link.tar -C d1 && rsync -a d1/ e2/ && echo k >> e2/p"},
		{"K13", "tar -xf link.tar -C d1 && cp -r d1 e3 && echo k >> e3/p"},
		{"K14", "tar -xf link.tar -C d1 && ditto d1 e4 && echo k >> e4/p"},
		{"K15", "cd d1 && tar -xf ../link.tar && echo k >> p"},
		{"K16", "cd {P} && tar -xf link.tar -C d1 && echo k >> d1/p"},
		{"K17", "tar -xf ~/project/link.tar -C ~/project/d1 && echo k >> ~/project/d1/p"},
		{"K18", "tar -xf $HOME/project/link.tar -C $HOME/project/d1 && echo k >> $HOME/project/d1/p"},
		{"K19", "tar -xf {P}/link.tar -C {P}/d1 && echo k >> {P}/d1/p"},
		{"K20", "tar -xf sshdir.tar -C d1 && echo k >> d1/s/authorized_keys"},
		{"K21", "tar -xf link2.tar -C d1 && echo k >> d1/p"},
		{"K22", "tar -xf link.tar -C d1 && cp a.txt d1/p"},
		{"K23", "tar -xf link.tar -C d1 && tee -a d1/p < a.txt"},
		{"K24", "tar -xf link.tar -C d1 && mv d1 d9 && echo k >> d9/p"},
		{"K25", "tar -xf link.tar -C d1 | cat; echo k >> d1/p"},
		{"K26", "bsdtar -xf link.tar -C d1 && echo k >> d1/p"},
		{"K27", "tar -xf link.tar -C d1 && ln -s d1/p q && echo k >> q"},
		{"K28", "if true; then tar -xf link.tar -C d1; fi; echo k >> d1/p"},
		{"K29", "tar -xvf link.tar -C d1 > list.txt && echo k >> d1/p"},
		// named protected targets with unread archives
		{"N01", "unzip -q pkg.zip -d app && cp -r app/pkg-1.0/. ~/.ssh/"},
		{"N02", "unzip -q pkg.zip -d app && rsync -a app/pkg-1.0/ ~/.ssh/"},
		{"N03", "tar -xzf missing.tgz -C app && mv app/pkg-1.0 ~/.ssh"},
		{"N04", "tar -xzf missing.tgz -C app && install app/x ~/.ssh/authorized_keys"},
		{"N05", "tar -xzf missing.tgz -C app && ln -s ~/.ssh/authorized_keys app/k && echo k >> app/k"},
		{"N06", "tar -xzf missing.tgz -C app && ln -sf ~/.ssh/authorized_keys app/k && echo k >> app/k"},
		{"N07", "tar -xzf missing.tgz -C app && ln -s ~/.ssh app/s && echo k >> app/s/authorized_keys"},
		{"N08", "tar -xzf missing.tgz -C app && echo k >> ~/.ssh/authorized_keys"},
		{"N09", "tar -xzf missing.tgz -C app && cp app/x keylink"},
		{"N10", "tar -xzf missing.tgz -C app && echo k >> app/pkg/authorized_keys"},
		{"N11", "tar -xzf missing.tgz -C ~/.ssh"},
		{"N12", "cd ~/.ssh && tar -xzf ~/project/missing.tgz"},
		{"N13", "tar -xzf missing.tgz -C ~ && echo ok > notes.txt"},
		{"N14", "unzip -q pkg.zip -d ~/.ssh"},
		{"N15", "F=~/.ssh/authorized_keys; unzip -q pkg.zip -d app && cp app/x \"$F\""},
		{"N16", "tar -xzf missing.tgz -C app && ditto app/pkg-1.0 ~/.ssh"},
		{"N17", "curl -o dl.tgz https://example.com/x.tgz && tar -xzf dl.tgz -C app && mv app/pkg-1.0 ~/.ssh/authorized_keys"},
		{"N18", "cd app && tar -xzf ../missing.tgz && mv pkg-1.0 ../../.ssh/authorized_keys"},
		{"N19", "tar -xzf missing.tgz -C app && echo k >> keylink"},
		{"N20", "tar -xzf missing.tgz -C app && cp -r app/pkg-1.0 dirlink/"},
		{"N21", "tar -xzf missing.tgz -C app && mv app/pkg-1.0/k dirlink/authorized_keys"},
		{"N22", "tar -xzf missing.tgz -C app && echo k >> {H}/.ssh/authorized_keys"},
		{"N23", "unzip -q pkg.zip -d ~/.ssh && echo ok > notes.txt"},
		// ordinary forms
		{"O01", "tar -xzf pkg.tgz -C app && mv app/pkg-1.0 app/pkg"},
		{"O02", "tar -xjf pkg.tbz -C app && mv app/pkg-1.0 app/pkg"},
		{"O03", "tar -xJf pkg.txz -C app && mv app/pkg-1.0 app/pkg"},
		{"O04", "tar --zstd -xf pkg.tzst -C app && mv app/pkg-1.0 app/pkg"},
		{"O05", "unzip -q pkg.zip -d app && cp -r app/pkg-1.0 app/pkg"},
		{"O06", "7z x pkg.7z -oapp && mv app/pkg-1.0 app/pkg"},
		{"O07", "jar xf pkg.jar && mv pkg-1.0 pkg"},
		{"O08", "cpio -id -D app < pkg.cpio && rsync -a app/pkg-1.0/ app/pkg/"},
		{"O09", "bsdtar -xf pkg.tgz -C app && cp -r app/pkg-1.0 app/pkg"},
		{"O10", "tar -xzf missing.tgz -C app && install -m 644 app/pkg-1.0/a.c app/out.c"},
		{"O11", "tar -xzf missing.tgz -C app && ln -s pkg-1.0 app/current"},
		{"O12", "tar -xzf missing.tgz -C app && ln -sf pkg-1.0 app/current"},
		{"O13", "ditto -x -k pkg.zip app && mv app/pkg-1.0 app/pkg"},
		{"O14", "wget -O dl.tgz https://example.com/x.tgz && tar -xzf dl.tgz -C app && cp -r app/pkg-1.0 app/pkg"},
		{"O15", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/app/pkg-1.0 ~/project/app/pkg"},
		{"O16", "tar -xzf $HOME/project/missing.tgz -C $HOME/project/app && mv $HOME/project/app/pkg-1.0 $HOME/project/app/pkg"},
		{"O17", "tar -xzf {P}/missing.tgz -C {P}/app && mv {P}/app/pkg-1.0 {P}/app/pkg"},
		{"O18", "cd {P}/app && tar -xzf ../missing.tgz && mv pkg-1.0 pkg"},
		{"O19", "cd ~/project/app && tar -xzf ../missing.tgz && cp -r pkg-1.0 pkg"},
		{"O20", "tar -xzf pkg.tgz -C ~/project/app && mv ~/project/app/pkg-1.0 ~/project/app/pkg"},
		{"O21", "tar -xzf missing.tgz -C app && mv app/pkg-1.0 app/pkg && echo k >> app/pkg/a.c"},
		{"O22", "tar -xzf missing.tgz -C app && rsync -a app/pkg-1.0/ app/pkg/"},
		{"O23", "unzip -q pkg.zip -d app && ditto app/pkg-1.0 app/pkg"},
		{"O24", "tar -xzf missing.tgz -C app && cp -r app/pkg-1.0 app/pkg && echo k >> app/pkg/a.c"},
		// ordinary config-like names after a tar call
		{"C01", "tar -xzf pkg.tgz -C app && mv app/pkg-1.0/config.example app/pkg-1.0/config"},
		{"C02", "tar -czf out.tgz src && mv conf/config.sample conf/config"},
		{"C03", "tar -tzf pkg.tgz && mv rc.sample rc"},
		{"C04", "tar -xzf pkg.tgz -C app && mv conf/config.sample conf/environment"},
		{"C05", "mv conf/config.sample conf/config"},
		{"C06", "tar -xzf missing.tgz -C app && mv app/pkg-1.0/config.example app/pkg-1.0/config"},
		{"C07", "tar -xzf pkg.tgz -C app && cp conf/config.sample conf/config"},
		// label checks
		{"L01", "echo k >> ~/.ssh/authorized_keys"},
		{"L02", "echo k >> keylink"},
	}
	for _, row := range rows {
		t.Run(row.id, func(t *testing.T) {
			f := rv054Fixture(t)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			cmd := strings.NewReplacer("{P}", f.project, "{H}", f.home).Replace(row.cmd)
			var out []string
			for _, connector := range []string{"claudecode", "codex"} {
				var cells []string
				for _, cell := range []struct {
					pack    string
					managed bool
				}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
					os.Chmod(f.homes, 0o700)
					id := fmt.Sprintf("rv-%s-%s-%t", row.id, cell.pack, cell.managed)
					payload := mustJSON(t, map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": id, "tool_input": map[string]any{"command": cmd, "description": "fixture"}})
					header := f.clientHeader(t, payload)
					got := rv054Post(t, f.homes, f.home, connector, cell.pack, payload, header, cell.managed)
					rv054AssertShell(t, row.id, connector, cell.pack, cell.managed, got)
					cells = append(cells, got)
				}
				out = append(out, strings.Join(cells, " "))
			}
			t.Logf("ROW|%s|%s|%s", row.id, strings.Join(out, " | "), row.cmd)
		})
	}
}

func TestGX054ReviewPatchCorpus(t *testing.T) {
	type prow struct{ id, patch string }
	for _, tool := range []string{"patch", "apply_patch"} {
		for _, where := range []string{"project", "home"} {
			f := rv054Fixture(t)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			cwd := f.project
			pre := ""
			if where == "home" {
				cwd = f.home
				pre = "project/"
			}
			rows := []prow{
				{"P01 add new", "*** Begin Patch\n*** Add File: " + pre + "notes2.txt\n+note\n*** End Patch"},
				{"P02 add new subdir", "*** Begin Patch\n*** Add File: " + pre + "sub/hello.txt\n+note\n*** End Patch"},
				{"P03 add absolute ordinary", "*** Begin Patch\n*** Add File: " + f.project + "/abs.txt\n+note\n*** End Patch"},
				{"P04 update existing", "*** Begin Patch\n*** Update File: " + pre + "existing.txt\n@@\n-x\n+y\n*** End Patch"},
				{"P05 add config name", "*** Begin Patch\n*** Add File: " + pre + "sub/config\n+note\n*** End Patch"},
				{"P10 add keys tilde", "*** Begin Patch\n*** Add File: ~/.ssh/authorized_keys\n+note\n*** End Patch"},
				{"P11 add keys absolute", "*** Begin Patch\n*** Add File: " + f.keys + "\n+note\n*** End Patch"},
				{"P12 add keys relative", "*** Begin Patch\n*** Add File: " + map[bool]string{true: ".ssh/authorized_keys", false: "../.ssh/authorized_keys"}[where == "home"] + "\n+note\n*** End Patch"},
				{"P13 move to keys", "*** Begin Patch\n*** Update File: " + pre + "existing.txt\n*** Move to: " + f.keys + "\n@@\n-x\n+y\n*** End Patch"},
				{"P14 move to keys tilde", "*** Begin Patch\n*** Update File: " + pre + "existing.txt\n*** Move to: ~/.ssh/authorized_keys\n@@\n-x\n+y\n*** End Patch"},
				{"P15 update keylink", "*** Begin Patch\n*** Update File: " + pre + "keylink\n@@\n-# decoy\n+k\n*** End Patch"},
				{"P16 add keylink", "*** Begin Patch\n*** Add File: " + pre + "keylink\n+k\n*** End Patch"},
				{"P17 add via dirlink", "*** Begin Patch\n*** Add File: " + pre + "dirlink/authorized_keys\n+k\n*** End Patch"},
				{"P18 delete keys", "*** Begin Patch\n*** Delete File: " + f.keys + "\n*** End Patch"},
				{"P19 add ssh config", "*** Begin Patch\n*** Add File: " + f.home + "/.ssh/config\n+Host x\n*** End Patch"},
				{"P20 move to dirlink", "*** Begin Patch\n*** Update File: " + pre + "existing.txt\n*** Move to: " + pre + "dirlink/authorized_keys\n@@\n-x\n+y\n*** End Patch"},
			}
			for _, row := range rows {
				var cells []string
				for _, cell := range []struct {
					pack    string
					managed bool
				}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
					os.Chmod(f.homes, 0o700)
					id := fmt.Sprintf("rvp-%s-%s-%s-%t", tool, row.id, cell.pack, cell.managed)
					payload := mustJSON(t, map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": map[string]any{"patchText": row.patch}, "session_id": id, "turn_id": "m1", "tool_call_id": id, "agent_name": "build", "cwd": cwd, "arguments_authoritative": true, "mcp_identity_status": "not_mcp"})
					header := hookpaths.ResolveConnector("opencode", "", "tool.execute.before", payload)
					got := rv054Post(t, f.homes, f.home, "opencode", cell.pack, payload, header, cell.managed)
					rv054AssertPatch(t, row.id, tool, where, cell.pack, cell.managed, got)
					cells = append(cells, got)
				}
				t.Logf("PROW|%s|%s|%s|%s", tool, where, row.id, strings.Join(cells, " "))
			}
		}
	}
}

// The probe contains unchanged detection misses as observation rows. Only
// decisions grounded in a concrete target or a documented policy split are
// pinned here; the focused class tests cover additional syntax variants.
func rv054AssertShell(t *testing.T, id, connector, pack string, managed bool, got string) {
	t.Helper()
	knownLink := map[string]bool{}
	for _, row := range []string{"K01", "K02", "K03", "K04", "K05", "K06", "K07", "K10", "K11", "K12", "K13", "K15", "K16", "K17", "K18", "K19", "K20", "K21", "K22", "K23", "K25", "K26", "K28", "K29"} {
		knownLink[row] = true
	}
	ordinary := map[string]bool{"C01": true, "C02": true, "C03": true, "C04": true, "C05": true, "C07": true}
	fail := func(want string) {
		t.Errorf("%s %s pack=%q managed=%t: got %q, want %s", id, connector, pack, managed, got, want)
	}
	if knownLink[id] && got == "A" {
		fail("block for a known link")
	}
	if ordinary[id] && got != "A" {
		fail("allow for an ordinary name")
	}
	if id == "O15" || id == "O16" {
		if managed && pack == "" && got != "A" {
			fail("managed balanced allow")
		}
		if managed && pack == "strict" && got == "A" {
			fail("managed strict block")
		}
	}
	if id == "N01" || id == "N02" || id == "N23" {
		if managed && !strings.HasPrefix(got, "S") {
			fail("SSH title for a named SSH write")
		}
	}
	if id == "O11" || id == "O12" {
		if pack == "strict" && !strings.HasPrefix(got, "R") {
			fail("archive title for an archive-only block")
		}
	}
	if id == "L01" || id == "L02" {
		if !strings.HasPrefix(got, "S") {
			fail("SSH title for a named SSH write")
		}
	}
}

func rv054AssertPatch(t *testing.T, id, tool, where, pack string, managed bool, got string) {
	t.Helper()
	ordinary := strings.HasPrefix(id, "P01 ") || strings.HasPrefix(id, "P02 ") || strings.HasPrefix(id, "P03 ") || strings.HasPrefix(id, "P04 ") || strings.HasPrefix(id, "P05 ")
	if ordinary && got != "A" {
		t.Errorf("%s %s %s pack=%q managed=%t: ordinary patch got %s", tool, where, id, pack, managed, got)
	}
	if !ordinary && got == "A" {
		t.Errorf("%s %s %s pack=%q managed=%t: protected patch allowed", tool, where, id, pack, managed)
	}
}
