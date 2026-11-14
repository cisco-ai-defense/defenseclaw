// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hp7ClientRow struct {
	name, command, managedWant, perUserWant string
}

func checkHP7ClientRows(t *testing.T, f b36ManagedHookFixture, rows []hp7ClientRow) {
	t.Helper()
	for _, name := range []string{"a.txt", "b.txt", "out.txt", "out2.txt", "out3.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		cells := everyMode(row.name, payloads[i], headers[i])
		for _, cell := range cells {
			cell.benignPerUserBlock = row.managedWant == "allow" && row.perUserWant == "block"
		}
		calls = append(calls, cells...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		row := rows[i/4]
		want := row.perUserWant
		if call.managed {
			want = row.managedWant
		}
		t.Logf("HP7ROW %s | %s | want %s", call.name, call.verdict, want)
		if want != "" && call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

// rel-1-0-6:GAP-0428: printf -vNAME, including a quoted name suffix,
// rebinds the destination. A dynamic first argument cannot prove safety.
func TestGAP0428PrintfBoundDestinationsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	checkHP7ClientRows(t, f, []hp7ClientRow{
		{"GAP0428/attached", `f=a.txt; printf -vf %s keylink; echo m >> "$f"`, "block", "block"},
		{"GAP0428/attached-benign", `f=a.txt; printf -vf %s b.txt; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/quoted-name", `f=a.txt; printf -v"f" %s keylink; echo m >> "$f"`, "block", "block"},
		{"GAP0428/quoted-name-benign", `f=a.txt; printf -v"f" %s b.txt; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/dynamic-option", `f=a.txt; opt=-vf; printf "$opt" %s keylink; echo m >> "$f"`, "block", "block"},
		{"GAP0428/dynamic-option-benign", `f=a.txt; opt=-vf; printf "$opt" %s b.txt; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/escaped-attached", `f=a.txt; printf -vf 'key\x6cink'; echo m >> "$f"`, "block", "block"},
		{"GAP0428/escaped-attached-benign", `f=a.txt; printf -vf 'b.\x74xt'; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/escaped-separate", `f=a.txt; printf -v f 'key\x6cink'; echo m >> "$f"`, "block", "block"},
		{"GAP0428/escaped-separate-benign", `f=a.txt; printf -v f 'b.\x74xt'; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/escaped-subst-attached", `f=a.txt; printf -vf 'key\x6cink%s' ''; echo m >> "$f"`, "block", "block"},
		{"GAP0428/escaped-subst-attached-benign", `f=a.txt; printf -vf 'b.\x74xt%s' ''; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/escaped-subst-separate", `f=a.txt; printf -v f 'key\x6cink%s' ''; echo m >> "$f"`, "block", "block"},
		{"GAP0428/escaped-subst-separate-benign", `f=a.txt; printf -v f 'b.\x74xt%s' ''; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/escaped-subst-no-arg-attached", `f=a.txt; printf -vf 'key\x6cink%s'; echo m >> "$f"`, "block", "block"},
		{"GAP0428/escaped-subst-no-arg-attached-benign", `f=a.txt; printf -vf 'b.\x74xt%s'; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/escaped-subst-no-arg-separate", `f=a.txt; printf -v f 'key\x6cink%s'; echo m >> "$f"`, "block", "block"},
		{"GAP0428/escaped-subst-no-arg-separate-benign", `f=a.txt; printf -v f 'b.\x74xt%s'; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/octal-attached", `f=a.txt; printf -vf 'key\154ink'; echo m >> "$f"`, "block", "block"},
		{"GAP0428/octal-attached-benign", `f=a.txt; printf -vf 'b.\164xt'; echo m >> "$f"`, "allow", "allow"},
		{"GAP0428/unicode-separate", `f=a.txt; printf -v f 'key\u006cink'; echo m >> "$f"`, "block", "block"},
		{"GAP0428/unicode-separate-benign", `f=a.txt; printf -v f 'b.\u0074xt'; echo m >> "$f"`, "allow", "allow"},
	})
}

func TestGAP0428DynamicPrintfRedirectOrderFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	checkHP7ClientRows(t, f, []hp7ClientRow{
		{"GAP0428/dynamic-same-redirect", `f=keylink; f=a.txt; printf "$fmt" >> "$f"`, "allow", "block"},
		{"GAP0428/fixed-same-redirect", `f=keylink; f=a.txt; printf %s m >> "$f"`, "allow", "block"},
		{"GAP0428/dynamic-later-target", `f=a.txt; opt=-vf; printf "$opt" %s keylink; echo m >> "$f"`, "block", "block"},
	})
}

// rel-1-0-6:GAP-0430: a fixed loop destination remains visible after a
// no-op prefix and with a simple copy or move option and extra body call.
func TestGAP0430LoopCopyNeighboursFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	rows := []hp7ClientRow{
		{"cd-prefix", `cd . && for f in out2.txt keylink; do cp a.txt $f; done`, "block", "block"},
		{"second-statement", `true; for f in out2.txt keylink; do cp a.txt $f; done`, "block", "block"},
		{"cp-option", `for f in out2.txt keylink; do cp -f a.txt $f; done`, "block", "block"},
		{"mv", `for f in out2.txt keylink; do mv a.txt $f; done`, "block", "block"},
		{"two-body", `for f in out2.txt keylink; do cp a.txt $f; echo ok; done`, "block", "block"},
		{"install-option", `for f in out2.txt keylink; do install -m 644 a.txt $f; done`, "block", "block"},
	}
	var paired []hp7ClientRow
	for _, row := range rows {
		row.name = "GAP0430/" + row.name
		paired = append(paired, row)
		paired = append(paired, hp7ClientRow{row.name + "-benign", strings.ReplaceAll(row.command, "keylink", "out3.txt"), "allow", "allow"})
	}
	checkHP7ClientRows(t, f, paired)
}

// rel-1-0-6:GAP-0431: the final move must not be hidden by an earlier
// ordinary redirect. The HOME row pins the per-user compactor exemption;
// managed HOME rebinding is tracked separately in GAP-0418.
func TestGAP0431MvAndHomeRowsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	checkHP7ClientRows(t, f, []hp7ClientRow{
		{"GAP0431/mv-after-redirect", `g=keylink; f=a.txt; echo m >> "$f"; mv b.txt "$g"`, "block", "block"},
		{"GAP0431/mv-after-redirect-benign", `g=out.txt; f=a.txt; echo m >> "$f"; mv b.txt "$g"`, "allow", "allow"},
		{"GAP0431/home-compact", "HOME=" + f.project + "; " + hp3r4IfDefaults(10, `echo m >> ~/keylink`), "", "block"},
		{"GAP0431/home-compact-benign", "HOME=" + f.project + "; " + hp3r4IfDefaults(10, `echo m >> ~/out.txt`), "allow", "allow"},
	})
}
