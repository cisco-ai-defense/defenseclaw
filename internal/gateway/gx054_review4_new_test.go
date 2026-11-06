// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Reviewer probe round 3: gx054 producer forms and archive bounds.
package gateway

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func rv4BigTgz(t *testing.T, path string, members int, bigBytes int64) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zw := gzip.NewWriter(file)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "node-v1/", Typeflag: tar.TypeDir, Mode: 0o755})
	for i := 0; i < members; i++ {
		tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("node-v1/src/f%05d.c", i), Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
		tw.Write([]byte("x\n"))
	}
	if bigBytes > 0 {
		tw.WriteHeader(&tar.Header{Name: "node-v1/deps/blob.bin", Typeflag: tar.TypeReg, Mode: 0o644, Size: bigBytes})
		chunk := make([]byte, 1<<20)
		for left := bigBytes; left > 0; {
			n := int64(len(chunk))
			if left < n {
				n = left
			}
			tw.Write(chunk[:n])
			left -= n
		}
	}
	tw.Close()
	zw.Close()
}

func rv4Extra(t *testing.T, f b36ManagedHookFixture, big bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.project, "link.tar"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(f.project, "link.part1"), raw[:100], 0o600)
	os.WriteFile(filepath.Join(f.project, "link.part2"), raw[100:], 0o600)
	sraw, _ := os.ReadFile(filepath.Join(f.project, "sshdir.tar"))
	os.WriteFile(filepath.Join(f.project, "ssh.part1"), sraw[:100], 0o600)
	os.WriteFile(filepath.Join(f.project, "ssh.part2"), sraw[100:], 0o600)
	if big {
		rv4BigTgz(t, filepath.Join(f.project, "node.tgz"), 5000, 0)
		rv4BigTgz(t, filepath.Join(f.project, "blob.tgz"), 3, 80<<20)
	}
	os.WriteFile(filepath.Join(f.project, "fake.tgz"), []byte("fixture archive"), 0o600)
	os.MkdirAll(filepath.Join(f.project, "big"), 0o700)
}

func rv4Header(t *testing.T, f b36ManagedHookFixture, connector string, payload []byte) string {
	t.Helper()
	os.Chmod(f.homes, 0o700)
	if connector == "codex" {
		return hookpaths.ResolveConnector("codex", "", "PreToolUse", payload)
	}
	return hookpaths.ResolveConnector("claudecode", "", "", payload)
}

func TestRV4NewForms(t *testing.T) {
	rows := []struct{ id, cmd string }{
		// stdin producers and pipelines carrying a keys-link archive (expect block everywhere)
		{"N01", "zstd -dc link.tzst | tar -xf - -C d1 && echo k >> d1/p"},
		{"N02", "zstd -d < link.tzst | tar -x -C d1; echo k >> d1/p"},
		{"N03", "tar -I zstd -xf link.tzst -C d1 && echo k >> d1/p"},
		{"N04", "zstdcat link.tzst | tar -xf - -C d1 && echo k >> d1/p"},
		{"N05", "xz -dc link.txz | tar -xf - -C d1 && echo k >> d1/p"},
		{"N06", "bzip2 -dc link.tbz | tar -xf - -C d1 && echo k >> d1/p"},
		{"N07", "cat < link.tar | tar -xf - -C d1 && echo k >> d1/p"},
		{"N08", "dd if=link.tar status=none | tar -xf - -C d1 && echo k >> d1/p"},
		{"N09", "cat link.tar | gzip | tar -xzf - -C d1 && echo k >> d1/p"},
		{"N10", "cat link.tar | (cd d1 && tar -xf -) && echo k >> d1/p"},
		{"N11", "gzip -dc < link.tgz | tar -xf - -C d1 && echo k >> d1/p"},
		{"N12", "zcat < link.tgz | tar -xf - -C d1 && echo k >> d1/p"},
		{"N13", "tar -xf - -C d1 <link.tar && cp a.txt d1/p"},
		{"N14", "tar -C d1 -xf /dev/fd/0 < link.tar && echo k >> d1/p"},
		// tee'd archive
		{"T01", "cat link.tar | tee x.tar | tar -xf - -C d1 && echo k >> d1/p"},
		{"T02", "tee x.tar < link.tar > /dev/null && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"T03", "cat link.tar | tee x.tar > /dev/null; tar -xf x.tar -C d1; echo k >> d1/p"},
		{"T04", "tee -a x.tar < link.tar >/dev/null && tar -xf x.tar -C d1 && echo k >> d1/p"},
		// process substitution
		{"P01", "tar -xf <(cat link.tar) -C d1 && echo k >> d1/p"},
		{"P02", "tar -xf - -C d1 < <(cat link.tar) && echo k >> d1/p"},
		{"P03", "tar -xzf <(gzip -c link.tar) -C d1 && echo k >> d1/p"},
		{"P04", "cat <(cat link.tar) | tar -xf - -C d1 && echo k >> d1/p"},
		// split archive concatenated
		{"C01", "cat link.part1 link.part2 > x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"C02", "cat link.part1 link.part2 | tar -xf - -C d1 && echo k >> d1/p"},
		{"C03", "cat link.part1 > x.tar; cat link.part2 >> x.tar; tar -xf x.tar -C d1; echo k >> d1/p"},
		{"C04", "cat ssh.part1 ssh.part2 > x.tar && tar -xf x.tar -C d1 && mv a.txt d1/s/config"},
		// hard link then mv, other rewrite chains
		{"L01", "ln link.tar x.tar && mv x.tar y.tar && tar -xf y.tar -C d1 && echo k >> d1/p"},
		{"L02", "ln link.tar x.tar; mv x.tar y.tar; tar -xf - -C d1 < y.tar; echo k >> d1/p"},
		{"L03", "cp link.tar x.tar && mv x.tar y.tar && tar -xf y.tar -C d1 && echo k >> d1/p"},
		{"L04", "ln -s link.tar x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"L05", "gzip -c link.tar > x.tgz && tar -xzf x.tgz -C d1 && echo k >> d1/p"},
		{"L06", "cp link.tar x.tar && gzip x.tar && tar -xzf x.tar.gz -C d1 && echo k >> d1/p"},
		{"L07", "install -m 600 link.tar x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"L08", "dd if=link.tar of=x.tar status=none && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"L09", "ln link.tar x.tar && mv x.tar y.tar && tar -xf y.tar -C d1 && mv a.txt d1/p"},
		{"L10", "ln sshdir.tar x.tar && mv x.tar y.tar && tar -xf y.tar -C d1 && mv a.txt d1/s/config"},
		{"L11", "tar -xf - -C d1 < sshdir.tar && mv a.txt d1/s/config"},
		{"L12", "cat sshdir.tar | tar -xf - -C d1 && cp a.txt d1/s/authorized_keys"},
		{"L13", "rsync link.tar x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		// copier home spellings (managed normalisation), protected twins block everywhere
		{"H31", "tar -xzf ~/project/missing.tgz -C ~/project/app && rsync -a ~/project/app/pkg-1.0/ ~/project/app/pkg/"},
		{"H32", "tar -xzf ~/project/missing.tgz -C ~/project/app && cp -a ${HOME}/project/app/pkg-1.0 ${HOME}/project/app/pkg"},
		{"H33", "tar -xzf ~/project/missing.tgz -C ~/project/app && ln -s ~/project/app/pkg-1.0 ~/project/app/pkg"},
		{"H34", "tar -xzf ~/project/missing.tgz -C ~/project/app && cp ~/project/a.txt ~/.ssh/authorized_keys"},
		{"H35", "tar -xzf ~/project/missing.tgz -C ~/project/app && install -m 600 ~/project/a.txt ~/.ssh/authorized_keys"},
		{"H36", "tar -xzf ~/project/missing.tgz -C ~/project/app && rsync ~/project/a.txt $HOME/.ssh/authorized_keys"},
		{"H37", "tar -xzf ~/project/missing.tgz -C ~/project/app && cp ~/project/a.txt \"$HOME\"/.ssh/rc"},
		{"H38", "tar -xf ~/project/sshdir.tar -C ~/project/d1 && cp ~/project/a.txt ~/project/d1/s/config"},
		{"H39", "tar -xf ~/project/sshdir.tar -C ~/project/d1 && install -m 600 ~/project/a.txt $HOME/project/d1/s/rc"},
		{"H40", "tar -xzf ~/project/missing.tgz -C ~/project/app && cp ~/project/a.txt ~/project/keylink"},
		// ordinary controls: expect balanced allow
		{"O01", "zstd -dc pkg.tzst | tar -xf - -C app && mv app/pkg-1.0 app/pkg"},
		{"O02", "cat pkg.tgz | tee copy.tgz | tar -xzf - -C app && mv app/pkg-1.0 app/pkg"},
		{"O03", "tar -xzf <(cat pkg.tgz) -C app && mv app/pkg-1.0 app/pkg"},
		{"O04", "ln pkg.tgz x.tgz && mv x.tgz y.tgz && tar -xzf y.tgz -C app && mv app/pkg-1.0 app/pkg"},
		{"O05", "xz -dc pkg.txz | tar -xf - -C app && cp -r app/pkg-1.0 app/pkg"},
		{"O06", "tar -xzf pkg.tgz -C /tmp && echo done > build-note.txt"},
		{"O07", "tar -xzf pkg.tgz -C app && echo done > build-note.txt"},
		// GAP-0634 extract in place then build logs
		{"G01", "tar xzf pkg.tgz && ./configure > build.log"},
		{"G02", "tar xzf node.tgz && ./configure > build.log"},
		{"G03", "tar xzf blob.tgz && ./configure > build.log"},
		{"G04", "tar xzf fake.tgz && ./configure > build.log"},
		{"G05", "tar xzf node.tgz && cd node-v1 && ./configure > config.log 2>&1"},
		{"G06", "tar xzf node.tgz && make > make.log 2>&1"},
		{"G07", "tar xzf missing.tgz && ./configure > build.log"},
		{"G08", "tar -xzf node.tgz -C big && echo done > build-note.txt"},
		{"G09", "tar -xzf blob.tgz -C /tmp && echo done > build-note.txt"},
		{"G10", "tar xzf link.tgz && ./configure > p"},
	}
	for _, row := range rows {
		t.Run(row.id, func(t *testing.T) {
			f := rv4oFixture(t)
			big := row.id == "G02" || row.id == "G03" || row.id == "G05" || row.id == "G06" || row.id == "G08" || row.id == "G09"
			rv4Extra(t, f, big)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			cmd := strings.NewReplacer("{P}", f.project, "{H}", f.home).Replace(row.cmd)
			var out []string
			start := time.Now()
			for _, connector := range []string{"claudecode", "codex"} {
				var cells []string
				for _, cell := range []struct {
					pack    string
					managed bool
				}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
					os.Chmod(f.homes, 0o700)
					id := fmt.Sprintf("rv4-%s-%s-%t", row.id, cell.pack, cell.managed)
					body := map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": id, "tool_input": map[string]any{"command": cmd}}
					if connector == "codex" {
						body["turn_id"] = "t-" + id
					}
					payload := mustJSON(t, body)
					header := rv4Header(t, f, connector, payload)
					cells = append(cells, rv4oPost(t, f.homes, f.home, connector, cell.pack, payload, header, cell.managed))
				}
				out = append(out, strings.Join(cells, " "))
			}
			rv4AssertCells(t, "new", row.id, out)
			t.Logf("ROW|%s|%s|%s|%dms", row.id, strings.Join(out, " | "), row.cmd, time.Since(start).Milliseconds())
		})
	}
}

// GAP-0627 parity with the connector-specific client header and env.
func TestRV4CodexParity(t *testing.T) {
	cmds := []string{
		`cd ~/clean && tar -xzf out.tgz -C $TMPDIR && mv $TMPDIR/src $TMPDIR/src-old && echo done`,
		`cd ~/clean; tar -xzf out.tgz -C $TMPDIR; mv $TMPDIR/src $TMPDIR/src-old; echo done`,
		`cd ~/clean && tar -xzf out.tgz -C $TMPDIR 2>/dev/null; mv $TMPDIR/src $TMPDIR/src-old 2>/dev/null; echo done`,
		`tar -xzf out.tgz -C $TMPDIR && mv $TMPDIR/src $TMPDIR/src-old && echo done`,
		`cd ~/clean && tar -xzf out.tgz -C $HOME/tmp && mv $HOME/tmp/src $HOME/tmp/src-old && echo done`,
		`cd ~/clean && tar -xzf out.tgz -C $TMPDIR && mv $TMPDIR/src $TMPDIR/src-old`,
		`cd ~/clean && tar -xzf out.tgz -C "$TMPDIR" && mv "$TMPDIR/src" "$TMPDIR/src-old" && echo done`,
		`cd ~/clean && tar -xzf out.tgz -C $TMPDIR && echo done > build-note.txt`,
		`cd ~/clean && tar -xzf out.tgz -C $TMPDIR && echo k >> ~/clean/keylink`,
		`cd ~/clean && tar -xzf link.tgz -C $TMPDIR && echo k >> $TMPDIR/p`,
	}
	for _, tmpMode := range []string{"set", "unset", "slash"} {
		for i, command := range cmds {
			t.Run(fmt.Sprintf("%s-%d", tmpMode, i), func(t *testing.T) {
				f := newB36ManagedHookFixture(t)
				t.Setenv("DEFENSECLAW_HOME", t.TempDir())
				clean := filepath.Join(f.home, "clean")
				tmp := filepath.Join(f.home, "tmp")
				os.MkdirAll(filepath.Join(clean, "src"), 0o700)
				os.MkdirAll(filepath.Join(tmp, "src"), 0o700)
				r107WriteTar(t, filepath.Join(clean, "out.tgz"), true, tar.Header{Name: "src/", Typeflag: tar.TypeDir}, tar.Header{Name: "src/a.c", Typeflag: tar.TypeReg})
				r107WriteTar(t, filepath.Join(clean, "link.tgz"), true, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: f.keys})
				os.Symlink("../.ssh/authorized_keys", filepath.Join(clean, "keylink"))
				switch tmpMode {
				case "set":
					t.Setenv("TMPDIR", tmp)
				case "slash":
					t.Setenv("TMPDIR", tmp+"/")
				default:
					os.Unsetenv("TMPDIR")
				}
				var out []string
				for _, connector := range []string{"claudecode", "codex"} {
					var cells []string
					for _, cell := range []struct {
						pack    string
						managed bool
					}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
						body := map[string]any{"session_id": "p", "hook_event_name": "PreToolUse", "cwd": clean, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "p", "tool_input": map[string]any{"command": command}}
						if connector == "codex" {
							body["turn_id"] = "t-1"
						}
						payload := mustJSON(t, body)
						header := rv4Header(t, f, connector, payload)
						cells = append(cells, rv4oPost(t, f.homes, f.home, connector, cell.pack, payload, header, cell.managed))
					}
					out = append(out, strings.Join(cells, " "))
				}
				rv4AssertCells(t, "par", fmt.Sprintf("%s-%d", tmpMode, i), out)
				t.Logf("PAR|%s|%d|%s|%s", tmpMode, i, strings.Join(out, " | "), command)
			})
		}
	}
}
