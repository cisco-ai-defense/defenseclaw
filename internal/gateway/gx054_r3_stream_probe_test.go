// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Reviewer probe round 2b retained as a regression.
package gateway

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRV054R3Probe(t *testing.T) {
	rows := []struct{ id, cmd string }{
		{"S01", "gzip -dc link.tgz | tar -xf - -C d1 && echo k >> d1/p"},
		{"S02", "zcat link.tgz | tar -x -C d1; echo k >> d1/p"},
		{"S03", "tar -x -C d1 < link.tar; echo k >> d1/p"},
		{"S04", "tar -xf /dev/stdin -C d1 < link.tar && echo k >> d1/p"},
		{"S05", "tar -xzf - -C d1 < link.tgz && echo k >> d1/p"},
		{"S06", "tar -xzf - -C app < pkg.tgz && mv app/pkg-1.0 app/pkg"},
		{"S07", "curl -sL https://example.com/x.tgz | tar -xz -C app && mv app/pkg-1.0 app/pkg"},
		{"S08", "cat link.tar > x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"S09", "{ cp link.tar x.tar; } && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"S10", "(cp link.tar x.tar) && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"S11", "cp link.tar x.tar\ntar -xf x.tar -C d1\necho k >> d1/p"},
		{"S12", "if true; then cp link.tar x.tar; fi; tar -xf x.tar -C d1; echo k >> d1/p"},
		{"S13", "cp link.tar pkg.tgz; tar -xf pkg.tgz -C d1; echo k >> d1/p"},
		{"S14", "ln link.tar x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"S15", "mv link.tar x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"S16", "for a in link.tar; do tar -xf $a -C d1; done; echo k >> d1/p"},
		{"S17", "A=link.tar; tar -xf $A -C d1; echo k >> d1/p"},
		{"S18", "A=link.tar; tar -xf \"$A\" -C d1 && echo k >> d1/p"},
		{"S19", "tar -xf link.tar -C d1 && cd d1 && echo k >> p"},
		{"S20", "pushd d1 && tar -xf ../link.tar && popd && echo k >> d1/p"},
		{"S21", "cat link.tar | tar -xf - -C d1 && cp a.txt d1/p"},
		{"S22", "tar -xf - -C d1 < link.tar; ln -s d1/p q"},
		{"S23", "tar -xzf - -C app < pkg.tgz && cp -r app/pkg-1.0 app/pkg"},
		{"S24", "gzip -dc pkg.tgz | tar -xf - -C app && mv app/pkg-1.0 app/pkg"},
		{"S25", "xz -dc link.txz | tar -xf - -C d1 && echo k >> d1/p"},
		{"S26", "zstd -dc link.tzst | tar -xf - -C d1 && echo k >> d1/p"},
		{"S27", "bzip2 -dc link.tbz | tar -xf - -C d1 && echo k >> d1/p"},
		{"S28", "ln -s link.tar x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"S29", "tee x.tar < link.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"S30", "dd if=link.tar of=x.tar && tar -xf x.tar -C d1 && echo k >> d1/p"},
		{"S31", "cat link.tar > x.tar && tar -x -C d1 < x.tar && echo k >> d1/p"},
		{"S32", "cat link.tar > x.tar && cat x.tar | tar -x -C d1 && echo k >> d1/p"},
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
					id := fmt.Sprintf("rv3-%s-%s-%t", row.id, cell.pack, cell.managed)
					payload := mustJSON(t, map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": id, "tool_input": map[string]any{"command": cmd, "description": "fixture"}})
					header := f.clientHeader(t, payload)
					cells = append(cells, rv054r2Post(t, f.homes, f.home, connector, cell.pack, payload, header, cell.managed))
				}
				out = append(out, strings.Join(cells, " "))
			}
			for _, cells := range out {
				if strings.HasPrefix(row.id, "S0") && row.id != "S06" && row.id != "S07" ||
					row.id == "S14" || row.id == "S21" || row.id == "S25" || row.id == "S26" || row.id == "S27" || row.id == "S28" || row.id == "S29" || row.id == "S30" || row.id == "S31" || row.id == "S32" {
					for _, cell := range strings.Fields(cells) {
						if cell == "A" {
							t.Errorf("%s: known archive link allowed: %s", row.id, cells)
						}
					}
				}
			}
			t.Logf("ROW|%s|%s|%s", row.id, strings.Join(out, " | "), strings.ReplaceAll(row.cmd, "\n", "\\n"))
		})
	}
}
