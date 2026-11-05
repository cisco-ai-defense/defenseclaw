// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The balanced tiers leave a sourced project-file destination alone when the
// existing path reading has no protected candidate. Managed hidden homes and
// strict tiers retain the conservative answer. A known link stays protected
// in every tier.
func TestGAP0481SourcedDestinationFollowsTier(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	source := filepath.Join(f.project, "setf.sh")
	rows := []struct {
		name, sourceValue, command string
		protected                  bool
	}{
		{"ordinary", "f=out.txt\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", false},
		{"source link", "f=keylink\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", true},
		{"source direct", "f=~/.ssh/authorized_keys\n", "f=a.txt; . ./setf.sh; echo m >> \"$f\"", true},
		{"initial link", "f=out.txt\n", "f=keylink; . ./setf.sh; echo m >> \"$f\"", true},
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
