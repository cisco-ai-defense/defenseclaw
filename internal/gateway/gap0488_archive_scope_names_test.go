// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0488ArchiveScopeAndOrdinaryMoveNames(t *testing.T) {
	f := gx054Fixture(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	for _, dir := range []string{"app", "conf", "src"} {
		if err := os.MkdirAll(filepath.Join(f.project, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"app/config.sample", "app/rc.sample", "conf/config.sample"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("ordinary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []struct {
		file, name, link string
		kind             byte
	}{
		{"plain.tar", "config.sample", "", tar.TypeReg},
		{"link.tar", "p", "../../.ssh/authorized_keys", tar.TypeSymlink},
	} {
		file, err := os.Create(filepath.Join(f.project, entry.file))
		if err != nil {
			t.Fatal(err)
		}
		writer := tar.NewWriter(file)
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Typeflag: entry.kind, Linkname: entry.link, Mode: 0o600}); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct{ name, command, want string }{
		{"extract then ordinary config", "tar -xf plain.tar -C app && mv app/config.sample app/config", "allow"},
		{"extract then ordinary rc", "tar --extract --file=plain.tar --directory=app && mv app/rc.sample app/rc", "allow"},
		{"extract then unrelated ordinary environment", "tar -xf plain.tar -C app && mv conf/config.sample conf/environment", "allow"},
		{"create then ordinary config", "tar -cf out.tar src && mv app/config.sample app/config", "allow"},
		{"list then ordinary rc", "tar -tf plain.tar && mv app/rc.sample app/rc", "allow"},
		{"linked archive with preceding statement", "true; tar -xf link.tar -C app; echo k >> app/p", "block"},
		{"linked archive with long options", "tar --extract --file=link.tar --directory=app && echo k >> app/p", "block"},
		{"linked archive copied through redirect", "cat link.tar > plain.tar; tar -xf plain.tar -C app && echo k >> app/p", "block"},
		{"linked archive copied through input redirect", "cat < link.tar > plain.tar; tar -xf plain.tar -C app && echo k >> app/p", "block"},
		{"linked archive copied through tee", "tee plain.tar < link.tar >/dev/null; tar -xf plain.tar -C app && echo k >> app/p", "block"},
		{"linked archive copied through pipe", "cat link.tar | tee plain.tar >/dev/null; tar -xf plain.tar -C app && echo k >> app/p", "block"},
		{"linked archive copied in extraction redirect", "tar -xf plain.tar -C app > \"$(cat link.tar | tee plain.tar >/dev/null; echo out)\" && echo k >> app/p", "block"},
		{"linked archive input redirect in extraction redirect", "tar -xf plain.tar -C app > \"$(cat < link.tar | tee plain.tar >/dev/null; echo out)\" && echo k >> app/p", "block"},
		{"linked archive copied through dd", "dd if=link.tar of=plain.tar status=none; tar -xf plain.tar -C app && echo k >> app/p", "block"},
		{"ordinary archive copied through pipe", "cat plain.tar | tee ordinary.tar >/dev/null; tar -xf ordinary.tar -C app && echo k >> app/config.sample", "allow"},
		{"pipe reader replaces linked input", "cat link.tar | cat plain.tar | tee ordinary.tar >/dev/null; tar -xf ordinary.tar -C app && echo k >> app/config.sample", "allow"},
		{"pipe dd replaces linked input", "cat link.tar | dd if=plain.tar of=ordinary.tar status=none; tar -xf ordinary.tar -C app && echo k >> app/config.sample", "allow"},
		{"direct keys target", "tar -xf plain.tar -C app && mv app/config.sample ~/.ssh/authorized_keys", "block"},
		{"known keys link target", "tar -xf plain.tar -C app && echo k >> keylink", "block"},
		{"create archive onto keys link", "tar -cf keylink src && mv app/config.sample app/config", "block"},
		{"create archive onto keys link alone", "tar -cf keylink src", "block"},
		{"create archive onto direct keys name", "tar -cf ~/.ssh/authorized_keys src", "block"},
	}
	strictWant := map[string]string{
		"extract then ordinary config":                "block",
		"extract then ordinary rc":                    "block",
		"extract then unrelated ordinary environment": "block",
		"create then ordinary config":                 "allow",
		"list then ordinary rc":                       "allow",
		"ordinary archive copied through pipe":        "block",
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex"} {
				for _, cell := range []struct {
					pack    string
					managed bool
				}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
					if err := os.Chmod(f.homes, 0o700); err != nil {
						t.Fatal(err)
					}
					id := fmt.Sprintf("g488b-r3-%s-%s-%s-%t", row.name, connector, cell.pack, cell.managed)
					payload := mustJSON(t, map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project,
						"permission_mode": "default", "tool_name": "Bash", "tool_use_id": id,
						"tool_input": map[string]any{"command": row.command, "description": "fixture"}})
					header := f.clientHeader(t, payload)
					got := gx054Verdict(t, f, connector, cell.pack, payload, header, cell.managed)
					want := row.want
					if cell.pack == "strict" && row.want == "allow" {
						var specified bool
						want, specified = strictWant[row.name]
						if !specified {
							continue
						}
					}
					if want == "allow" && got != "allow" || want == "block" && got == "allow" {
						t.Errorf("%s pack=%q managed=%t: got %s, want %s", connector, cell.pack, cell.managed, got, want)
					}
				}
			}
		})
	}
}
