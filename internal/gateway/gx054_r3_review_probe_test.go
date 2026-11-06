// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Reviewer probe round 2 retained as a regression.
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

func rv054r2Class(body string) string {
	if !(strings.Contains(body, `"deny"`) || strings.Contains(body, `"block"`)) {
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

func rv054r2Post(t *testing.T, homes, home, connector, pack string, payload []byte, header string, managed bool) string {
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
	return rv054r2Class(rec.Body.String())
}

func rv054r2Fixture(t *testing.T) b36ManagedHookFixture {
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
	r107WriteTar(t, filepath.Join(f.project, "cfg.tar"), false, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/config"})
	os.MkdirAll(filepath.Join(f.project, "deploy", ".ssh"), 0o700)
	os.MkdirAll(filepath.Join(f.project, "d2"), 0o700)
	os.WriteFile(filepath.Join(f.project, "list.txt"), []byte("link.tar\n"), 0o600)
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

func TestRV054R2Probe(t *testing.T) {
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
		// round 2: compound shapes around a gateway-readable keys-link tar
		{"K30", "tar -xf link.tar -C d1\necho k >> d1/p"},
		{"K31", "echo a\ntar -xf link.tar -C d1\necho k >> d1/p"},
		{"K32", "{ tar -xf link.tar -C d1; }; echo k >> d1/p"},
		{"K33", "{ tar -xf link.tar -C d1; echo k >> d1/p; }"},
		{"K34", "{ echo a; tar -xf link.tar -C d1; } && echo k >> d1/p"},
		{"K35", "(tar -xf link.tar -C d1); echo k >> d1/p"},
		{"K36", "(tar -xf link.tar -C d1 && echo k >> d1/p)"},
		{"K37", "(cd d1 && tar -xf ../link.tar) && echo k >> d1/p"},
		{"K38", "true && echo a && tar -xf link.tar -C d1 && echo k >> d1/p"},
		{"K39", "false || tar -xf link.tar -C d1 || true; echo k >> d1/p"},
		{"K40", "test -d d1 && tar -xf link.tar -C d1 || echo fail && echo k >> d1/p"},
		{"K41", "while read f; do tar -xf link.tar -C d1; done < a.txt; echo k >> d1/p"},
		{"K42", "while read f; do echo \"$f\"; done < a.txt; tar -xf link.tar -C d1; echo k >> d1/p"},
		{"K43", "tar -xf link.tar -C d1 && while read l; do echo \"$l\" >> d1/p; done < a.txt"},
		{"K44", "echo a | xargs tar -xf link.tar -C d1; echo k >> d1/p"},
		{"K45", "xargs -a a.txt tar -xf link.tar -C d1; echo k >> d1/p"},
		{"K46", "xargs -I{} tar -xf {} -C d1 < list.txt; echo k >> d1/p"},
		{"K47", "x=$(tar -xf link.tar -C d1); echo k >> d1/p"},
		{"K48", "echo \"$(tar -xf link.tar -C d1)\" && echo k >> d1/p"},
		{"K49", "cat <(tar -xf link.tar -C d1) && echo k >> d1/p"},
		{"K50", "tar -xvf link.tar -C d1 > >(cat) && echo k >> d1/p"},
		{"K51", "tar -xf link.tar -C d1 <<< x && echo k >> d1/p"},
		{"K52", "cat <<< x; tar -xf link.tar -C d1; echo k >> d1/p"},
		{"K53", "tar -xf - -C d1 < link.tar && echo k >> d1/p"},
		{"K54", "cat link.tar | tar -xf - -C d1 && echo k >> d1/p"},
		{"K55", "tar -xzf pkg.tgz -C d1 && tar -xf link.tar -C d1 && echo k >> d1/p"},
		{"K56", "for i in 1; do tar -xf link.tar -C d1; done; echo k >> d1/p"},
		{"K57", "if tar -xf link.tar -C d1; then echo k >> d1/p; fi"},
		{"K58", "tar -xf link.tar -C d1 & wait; echo k >> d1/p"},
		{"K59", "time tar -xf link.tar -C d1; echo k >> d1/p"},
		{"K60", "! tar -xf link.tar -C d1; echo k >> d1/p"},
		{"K61", "case x in x) tar -xf link.tar -C d1;; esac; echo k >> d1/p"},
		{"K62", "f() { tar -xf link.tar -C d1; }; f; echo k >> d1/p"},
		{"K63", "env LC_ALL=C tar -xf link.tar -C d1 && echo k >> d1/p"},
		{"K64", "command tar -xf link.tar -C d1 && echo k >> d1/p"},
		{"K65", "tar --extract --file=link.tar --directory=d1 && echo k >> d1/p"},
		{"K66", "tar xf link.tar -C d1 && echo k >> d1/p"},
		{"K67", "tar -C d1 -x -f link.tar && echo k >> d1/p"},
		{"K68", "echo a; echo b; echo c; tar -xf link.tar -C d1 2>&1 | tee log.txt; echo k >> d1/p"},
		{"K69", "tar -xf sshdir.tar -C d1; { echo k; } >> d1/s/authorized_keys"},
		{"K70", "(tar -xf sshdir.tar -C d1) && cp a.txt d1/s/config"},
		{"K71", "tar -xf link.tar -C d1 && tar -xf link.tar -C d2 && echo k >> d2/p"},
		{"K72", "mkdir -p d1 && tar -xf link.tar -C d1 && sed -i s/a/b/ d1/p"},
		{"K73", "tar -xf link.tar -C d1 && cat a.txt >> d1/p"},
		{"K74", "{ tar -xf link.tar -C d1 & }; wait; echo k >> d1/p"},
		{"K75", "tar -xf link.tar -C d1 && echo k | tee -a d1/p >/dev/null"},
		{"K76", "bash -c 'tar -xf link.tar -C d1' && echo k >> d1/p"},
		{"K77", "tar -xf link.tar -C d1 && bash -c 'echo k >> d1/p'"},
		{"K78", "tar -xf cfg.tar -C d1; echo 'Host x' >> d1/p"},
		{"K79", "tar -xzf link.tgz -C d1 > /dev/null 2>&1; echo k >> d1/p"},
		{"K80", "cd d1; tar -xf ../link.tar; cd ..; echo k >> d1/p"},
		{"K81", "tar -xf link.tar -C d1 || exit 1\necho k >> d1/p"},
		{"K82", "set -e; tar -xf link.tar -C d1; printf k >> d1/p"},
		// round 2: move names keyed on the proved extracted set
		{"M01", "tar -xzf pkg.tgz -C app && mv a.txt conf/authorized_keys"},
		{"M02", "tar -xzf missing.tgz -C app && mv a.txt conf/authorized_keys"},
		{"M03", "tar -xzf pkg.tgz -C app && cp a.txt conf/authorized_keys"},
		{"M04", "tar -xzf pkg.tgz -C app && echo k >> conf/authorized_keys"},
		{"M05", "tar -xzf missing.tgz -C app && echo k >> conf/authorized_keys"},
		{"M06", "mv a.txt conf/authorized_keys"},
		{"M07", "tar -xzf pkg.tgz -C app && mv app/pkg-1.0/config.example deploy/.ssh/config"},
		{"M08", "tar -xzf missing.tgz -C app && mv rc.sample deploy/.ssh/rc"},
		{"M09", "tar -xzf pkg.tgz -C app && mv a.txt deploy/.ssh/authorized_keys"},
		{"M10", "tar -xzf pkg.tgz -C app && mv app/pkg-1.0/config.example ~/.ssh/config"},
		{"M11", "tar -xzf missing.tgz -C app && mv rc.sample ~/.ssh/rc"},
		{"M12", "tar -xzf pkg.tgz -C app && mv a.txt dirlink/config"},
		{"M13", "tar -xzf missing.tgz -C app && mv rc.sample dirlink/rc"},
		{"M14", "tar -xzf pkg.tgz -C app && mv app/pkg-1.0 ~/.ssh"},
		{"M15", "tar -xzf pkg.tgz -C app && mv ~/.ssh ~/ssh-old"},
		{"M16", "tar -xzf pkg.tgz -C app && mv -t ~/.ssh app/pkg-1.0/config.example"},
		{"M17", "S=~/.ssh; tar -xzf pkg.tgz -C app && mv a.txt $S/config"},
		{"M18", "tar -xzf pkg.tgz -C app && mv a.txt {H}/.ssh/environment"},
		{"M19", "tar -xf sshdir.tar -C d1 && mv a.txt d1/s/config"},
		{"M20", "tar -xf sshdir.tar -C d1 && mv a.txt d1/s/rc"},
		{"M21", "tar -xf sshdir.tar -C d1 && mv a.txt d1/s/authorized_keys"},
		{"M22", "tar -xf link.tar -C d1 && mv a.txt d1/p"},
		{"M24", "tar -xzf pkg.tgz -C app && mv ~/.ssh/authorized_keys ~/ak.bak"},
		{"M25", "tar -xzf pkg.tgz -C app && mv a.txt deploy/.ssh"},
		{"M26", "tar -xzf pkg.tgz -C app && mv conf/config.sample conf/config"},
		{"M27", "mv a.txt dirlink/config"},
		{"M28", "tar -xzf missing.tgz -C app && mv a.txt app/authorized_keys"},
		{"M29", "cd deploy/.ssh && tar -xzf ../../pkg.tgz && mv pkg-1.0/config.example config"},
		{"M30", "cd ~/.ssh && tar -xzf ~/project/pkg.tgz -C ~/project/app && mv ~/project/app/pkg-1.0/config.example config"},
		{"M31", "cd ~/.ssh && tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/rc.sample rc"},
		{"M32", "tar -xzf pkg.tgz -C app && mv a.txt app/pkg-1.0/authorized_keys.example"},
		{"M33", "tar -xf sshdir.tar -C d1 && mv a.txt d1/s/"},
		{"M34", "tar -xf sshdir.tar -C d1 && mv app d1/s"},
		{"M35", "tar -xzf missing.tgz -C app && mv rc.sample app/rc"},
		{"M36", "tar -xzf pkg.tgz -C app && mv a.txt dirlink"},
		{"M37", "cp sshdir.tar alias.tar && tar -xf alias.tar -C d1 && mv a.txt d1/s/config"},
		{"M38", "ln sshdir.tar alias.tar && tar -xf alias.tar -C d1 && mv a.txt d1/s/config"},
		{"M39", "ln -s sshdir.tar alias.tar && tar -xf alias.tar -C d1 && mv a.txt d1/s/config"},
		{"M40", "cat sshdir.tar > alias.tar && tar -xf alias.tar -C d1 && mv a.txt d1/s/config"},
		{"M41", "tar -xf - -C d1 < sshdir.tar && mv a.txt d1/s/config"},
		{"M42", "cat sshdir.tar | tar -xf - -C d1 && mv a.txt d1/s/config"},
		{"M43", "cat sshdir.tar > alias.tar && cat alias.tar | tar -xf - -C d1 && mv a.txt d1/s/config"},
		{"M44", "ln -s sshdir.tar alias.tar && tar -xf - -C d1 < alias.tar && mv a.txt d1/s/config"},
		// round 2: managed home spellings
		{"H03", "tar -xzf ${HOME}/project/missing.tgz -C ${HOME}/project/app && mv ${HOME}/project/app/pkg-1.0 ${HOME}/project/app/pkg"},
		{"H04", "tar -xzf ~/project/missing.tgz -C ~/project/app && cp -r ~/project/app/pkg-1.0 ~/project/app/pkg"},
		{"H05", "tar -xzf ~/project/missing.tgz -C ~/project/app && rsync -a ~/project/app/pkg-1.0/ ~/project/app/pkg/"},
		{"H06", "tar -xzf ~/project/missing.tgz -C ~/project/app && install -m 644 ~/project/app/pkg-1.0/a.c ~/project/app/out.c"},
		{"H07", "tar -xzf ~/project/missing.tgz -C ~/project/app && echo k >> ~/project/app/pkg-1.0/a.c"},
		{"H08", "tar -xzf $HOME/project/missing.tgz -C $HOME/project/app && cp -r $HOME/project/app/pkg-1.0 $HOME/project/app/pkg"},
		{"H09", "tar -xzf ~/project/missing.tgz -C ~/project/app && ditto ~/project/app/pkg-1.0 ~/project/app/pkg"},
		{"H10", "cd ~/project && tar -xzf missing.tgz -C app && mv app/pkg-1.0 app/pkg"},
		{"H11", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/app/pkg-1.0 ~/.ssh"},
		{"H12", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/app/pkg-1.0/x ~/.ssh/authorized_keys"},
		{"H14", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/a.txt ~/project/dirlink/config"},
		{"H15", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/app/pkg-1.0/x ~/.ssh/config"},
		{"H16", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/app/pkg-1.0 ~/project/app/pkg && echo k >> ~/project/app/pkg/a.c"},
		{"H17", "tar -xzf missing.tgz -C app && mv ~/project/app/pkg-1.0 ~/project/app/pkg"},
		{"H18", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/app/pkg-1.0 app/pkg"},
		{"H19", "tar -xf ~/project/sshdir.tar -C ~/project/d1 && mv ~/project/a.txt ~/project/d1/s/config"},
		{"H20", "tar -xf ~/project/link.tar -C ~/project/d1 && mv ~/project/d1/p ~/project/d1/q && echo k >> ~/project/d1/q"},
		{"H21", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/app/pkg-1.0 ~/project/app/pkg-2.0 && cp ~/project/a.txt ~/project/keylink"},
		{"H22", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/a.txt ~/project/dirlink/"},
		{"H23", "tar -xzf ~/project/missing.tgz -C ~/project/app && mv ~/project/app/pkg-1.0 ~/project/dirlink/pkg"},
		{"H24", "tar -xzf $HOME/project/missing.tgz -C $HOME/project/app && install -m 644 $HOME/project/app/pkg-1.0/a.c $HOME/project/app/out.c"},
		{"H25", "tar -xzf $HOME/project/missing.tgz -C $HOME/project/app && rsync -a $HOME/project/app/pkg-1.0/ $HOME/project/app/pkg/"},
		{"H26", "tar -xzf $HOME/project/missing.tgz -C $HOME/project/app && ditto $HOME/project/app/pkg-1.0 $HOME/project/app/pkg"},
		{"H27", "tar -xzf ${HOME}/project/missing.tgz -C ${HOME}/project/app && cp -a ${HOME}/project/app/pkg-1.0 ${HOME}/project/app/pkg"},
		// label checks
		{"L01", "echo k >> ~/.ssh/authorized_keys"},
		{"L02", "echo k >> keylink"},
	}
	for _, row := range rows {
		t.Run(row.id, func(t *testing.T) {
			f := rv054r2Fixture(t)
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
					cells = append(cells, rv054r2Post(t, f.homes, f.home, connector, cell.pack, payload, header, cell.managed))
				}
				out = append(out, strings.Join(cells, " "))
			}
			// The review rows are a committed four-cell oracle. Each connector
			// must make the same decision in per-user and managed profiles.
			ordinary := map[string]string{
				"M01": "A A A A", "M02": "A A A A", "M07": "A A A A",
				"M08": "A A A A", "M09": "A A A A", "M25": "A A A A",
				"H04": "A A A B", "H05": "A A A B", "H06": "A A A B", "H08": "A A A B", "H09": "A A A B",
				"H24": "A A A B", "H25": "A A A B", "H26": "A A A B", "H27": "A B A B",
			}
			for _, cells := range out {
				if want, checked := ordinary[row.id]; checked {
					got := strings.Fields(cells)
					for i, expected := range strings.Fields(want) {
						if expected == "A" && got[i] != "A" || expected == "B" && got[i] == "A" {
							t.Errorf("%s cell %d: got %s, want %s", row.id, i, got[i], expected)
						}
					}
				}
				if row.id == "M19" || row.id == "M20" || row.id == "M21" || row.id == "M33" ||
					row.id == "M37" || row.id == "M38" || row.id == "M39" || row.id == "M40" ||
					row.id == "M41" || row.id == "M42" || row.id == "M43" || row.id == "M44" {
					for i, got := range strings.Fields(cells) {
						if got == "A" {
							t.Errorf("%s cell %d: known extracted SSH link allowed", row.id, i)
						}
					}
				}
			}
			t.Logf("ROW|%s|%s|%s", row.id, strings.Join(out, " | "), row.cmd)
		})
	}
}

func TestRV054R2Patch(t *testing.T) {
	type prow struct{ id, patch string }
	for _, tool := range []string{"patch", "apply_patch"} {
		for _, where := range []string{"project", "home"} {
			f := rv054r2Fixture(t)
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
					cells = append(cells, rv054r2Post(t, f.homes, f.home, "opencode", cell.pack, payload, header, cell.managed))
				}
				t.Logf("PROW|%s|%s|%s|%s", tool, where, row.id, strings.Join(cells, " "))
			}
		}
	}
}
