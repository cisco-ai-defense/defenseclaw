// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The balanced tiers leave a sourced project-file destination alone when the
// current source and known candidates are ordinary. Managed hidden homes and
// strict tiers retain the conservative answer. A known link stays protected
// in every tier.
func TestGAP0481SourcedDestinationFollowsTier(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	source := filepath.Join(f.project, "setf.sh")
	if err := os.Mkdir(filepath.Join(f.project, "reports"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.keys, filepath.Join(f.project, "key link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(f.keys, filepath.Join(f.project, "hardkey")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "writer.sh"), []byte("printf x >> ~/.ssh/authorized_keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, sourceValue, command string
		protected                  bool
	}{
		{"ordinary", "f=out.txt\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", false},
		{"printf", "f=out.txt\n", "f=a.txt; . ./setf.sh; printf '%s\\n' m >> \"$f\"", false},
		{"no-op between", "f=out.txt\n", "f=a.txt; . ./setf.sh; :; echo m >> \"$f\"", false},
		{"project subdirectory", "f=reports/b.txt\n", "f=reports/a.txt; . ./setf.sh; echo m >> \"$f\"", false},
		{"unquoted destination", "f=out.txt\n", "f=a.txt; . ./setf.sh; echo m >> $f", false},
		{"dot-relative destination", "f=./out.txt\n", "f=./a.txt; . ./setf.sh; echo m >> \"$f\"", false},
		{"spaced destination", "f='out file.txt'\n", "f='a file.txt'; . ./setf.sh; echo m >> \"$f\"", false},
		{"cat redirect", "f=out.txt\n", "f=a.txt; . ./setf.sh; cat input.txt >> \"$f\"", false},
		{"colon redirect", "f=out.txt\n", "f=a.txt; . ./setf.sh; : >> \"$f\"", false},
		{"overwrite redirect", "f=out.txt\n", "f=a.txt; . ./setf.sh; echo m > \"$f\"", false},
		{"absolute source path", "f=out.txt\n", fmt.Sprintf("f=a.txt; . %q; echo m >> \"$f\"", source), false},
		{"source with no-op", "f=out.txt\n:\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", false},
		{"source with export", "export f=out.txt\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", false},
		{"source export embedded tilde", "export f=out~file\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", false},
		{"source with conditional", "f=out.txt\nif test -n \"$UNSET\"; then f=other.txt; fi\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", false},
		{"conditional source", "f=out.txt\n", "f=a.txt; if test -n \"$UNSET\"; then . ./setf.sh; fi; echo m >> \"$f\"", false},
		{"source then binding", "f=out.txt\n", ". ./setf.sh; f=a.txt; echo m >> \"$f\"", false},
		{"source hardlink", "f=hardkey\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", true},
		{"source export protected", "export f=~/.ssh/authorized_keys\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", true},
		{"source conditional protected", "f=out.txt\nif test -n \"$UNSET\"; then f=keylink; fi\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", true},
		{"source link", "f=keylink\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", true},
		{"source direct", "f=~/.ssh/authorized_keys\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", true},
		{"source side effect", "f=out.txt\necho x >> ~/.ssh/authorized_keys\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", true},
		{"source function", "f=out.txt\necho() { printf x >> ~/.ssh/authorized_keys; }\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", true},
		{"initial link", "f=out.txt\n", "f=keylink; . ./setf.sh; echo m >> \"$f\"", true},
		{"spaced protected link", "f='key link'\n", "f='a file.txt'; . ./setf.sh; echo m >> \"$f\"", true},
		{"spaced initial link", "f='out file.txt'\n", "f='key link'; . ./setf.sh; echo m >> \"$f\"", true},
		{"writer named target", "f=out.txt\n", "f=a.txt; . ./setf.sh; cp a.txt ~/.ssh/authorized_keys >> \"$f\"", true},
		{"writer script target", "f=out.txt\n", "f=a.txt; . ./setf.sh; sh ./writer.sh >> \"$f\"", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if err := os.Chmod(f.homes, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source, []byte(row.sourceValue), 0o600); err != nil {
				t.Fatal(err)
			}
			payload := f.payload(t, row.command)
			header := f.clientHeader(t, payload)
			if _, ok := hookpaths.Decode(header); !ok {
				t.Fatal("client path evidence did not decode")
			}
			for _, pack := range []string{"default", "permissive", "strict"} {
				for _, connector := range []string{"claudecode", "codex"} {
					for _, managed := range []bool{false, true} {
						mode := os.FileMode(0o700)
						if managed {
							mode = 0
						}
						if err := os.Chmod(f.homes, mode); err != nil {
							t.Fatal(err)
						}
						call := &keyReadCall{
							api:       keyReadGateway(t, connector, pack, "action"),
							connector: connector, payload: payload, header: header, managed: managed,
						}
						call.answer(f.home)
						want := "allow"
						if row.protected || pack == "strict" || managed {
							want = "block"
						}
						if call.verdict != want {
							t.Errorf("%s %s managed=%v: verdict %s, want %s", pack, connector, managed, call.verdict, want)
						}
					}
				}
			}
		})
	}
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestGAP0481CurrentSourceAfterClientReading(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	source := filepath.Join(f.project, "setf.sh")
	if err := os.WriteFile(source, []byte("f=out.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := f.payload(t, `f=a.txt; . ./setf.sh; echo m >> "$f"`)
	header := f.clientHeader(t, payload)
	if err := os.WriteFile(source, []byte("f=keylink\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"claudecode", "codex"} {
		call := &keyReadCall{api: keyReadGateway(t, connector, "default", "action"),
			connector: connector, payload: payload, header: header}
		call.answer(f.home)
		if call.verdict != "block" {
			t.Errorf("%s current source changed after client reading: %s", connector, call.verdict)
		}
	}
}
