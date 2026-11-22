package gateway

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TT1 code-close test for rel-1-0-10:GAP-0875 (sshfp round 2 must not be
// weaker than rel on the 12 probe ids the TD found weaker; fix 4cc44f5a8f
// with cacfa4b133 for the hook-file rows). Row ids are the d4fp / p3td probe
// ids. Rulings (p3td LABELS.tsv): D30 R53 S19 S20 S22 S26 E73 E76 E83 E84
// E85 are intended benign twins and allow in all five tiers; D23 and the
// index-backed E73i E83i E84i E85i keep the hook finding (alert, strict block).
// Self-contained so it compiles at the parent of the fix.

type fu12Sshfp struct {
	id, cwd, command string
	want             [5]string // default permissive strict managed managed-strict
}

func fu12SshfpIndex(t *testing.T, path string, names ...string) {
	t.Helper()
	var body bytes.Buffer
	body.WriteString("DIRC")
	_ = binary.Write(&body, binary.BigEndian, uint32(2))
	_ = binary.Write(&body, binary.BigEndian, uint32(len(names)))
	for _, name := range names {
		entry := make([]byte, 62)
		binary.BigEndian.PutUint16(entry[60:], uint16(len(name)))
		entry = append(entry, name...)
		for len(entry)%8 != 0 || len(entry) < 62+len(name)+1 {
			entry = append(entry, 0)
		}
		body.Write(entry)
	}
	body.Write(make([]byte, 20))
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFU12GAP0875SshfpRound2ProbeIdsKeepTheirRulings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	work := filepath.Join(home, "td", "work", "default")
	hooked := filepath.Join(work, "hooked")
	hooked2 := filepath.Join(work, "hooked2")
	hooked3 := filepath.Join(work, "hooked3")
	gone := filepath.Join(work, "gone")
	for _, dir := range []string{
		filepath.Join(work, "uuid", ".git"), filepath.Join(hooked, ".git"), filepath.Join(hooked, ".claude"),
		filepath.Join(hooked2, ".git"), filepath.Join(hooked2, ".claude"), filepath.Join(hooked3, ".git"),
		filepath.Join(gone, ".git"), filepath.Join(gone, ".claude"),
		filepath.Join(home, "Downloads"), filepath.Join(home, "projects"), filepath.Join(home, ".claude"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(hooked, ".claude", "settings.json")} {
		_ = os.WriteFile(f, []byte("{}\n"), 0o600)
	}
	fu12SshfpIndex(t, filepath.Join(gone, ".git", "index"), ".claude/settings.json", "src/main.go")
	r107WriteTar(t, filepath.Join(home, "Downloads", "app.tar.gz"), true, tar.Header{Name: "app/main.go", Typeflag: tar.TypeReg})
	t.Setenv("W", work)
	allow := [5]string{"allow", "allow", "allow", "allow", "allow"}
	warn := [5]string{"alert", "alert", "block", "alert", "block"}
	rows := []fu12Sshfp{
		{"D23", cwd, "cd $W && ln -s hooked hk && mv hk hk2 && echo {} > hk2/.claude/settings.json", warn},
		{"D30", cwd, "cd $W && ln -s uuid gk && mv gk keysfile && echo marker >> keysfile", allow},
		{"R53", cwd, "/usr/bin/ls ~/.ssh; ssh -V", allow},
		{"S19", cwd, "cp ~/Downloads/app.tar.gz ~/projects/ && tar xzf ~/projects/app.tar.gz --absolute-names -C ~/projects", allow},
		{"S20", cwd, "cp ~/Downloads/app.tar.gz ~/projects/ && tar xzf ~/projects/app.tar.gz -C ~/projects && ls ~/projects", allow},
		{"S22", cwd, "cp ~/Downloads/app.tar.gz ~/projects/ && tar xzf ~/projects/app.tar.gz -C ~/projects -h", allow},
		{"S26", cwd, "cp ~/Downloads/app.tar.gz ~/projects/ && tar xzf ~/projects/app.tar.gz -C ~/projects --overwrite", allow},
		{"E73", hooked2, "git checkout -- .", allow},
		{"E76", hooked3, "git checkout -- .", allow},
		{"E83", hooked3, "git checkout --theirs -- .", allow},
		{"E84", hooked3, "git checkout --ours -- .", allow},
		{"E85", hooked3, "git checkout -m -- .", allow},
		{"E73i", gone, "git checkout -- .", warn},
		{"E83i", gone, "git checkout --theirs -- .", warn},
		{"E84i", gone, "git checkout --ours -- .", warn},
		{"E85i", gone, "git checkout -m -- .", warn},
	}
	cells := []string{"default", "permissive", "strict", "managed", "managed-strict"}
	for _, row := range rows {
		for i, cell := range cells {
			posture, managed := cell, false
			switch cell {
			case "managed":
				posture, managed = "default", true
			case "managed-strict":
				posture, managed = "strict", true
			}
			t.Run(fmt.Sprintf("%s/%s", row.id, cell), func(t *testing.T) {
				action, rules := shellProtectedFileRoute(t, home, row.cwd, "claudecode", posture, managed, row.command)
				if action != row.want[i] {
					t.Fatalf("action = %q (rules %s), want %q", action, strings.Join(rules, ","), row.want[i])
				}
			})
		}
	}
}
