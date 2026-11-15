// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// s7-sshfp round 2 (review s7-sshfpchk, rel-1-0-10:GAP-0715, GAP-0716,
// GAP-0717): three regressions of the GAP-0570..0572, GAP-0593 fixes against
// rel 9efb4f1799. Every row id (R.., E.., S.., G..) is the review's probe id;
// positives keep rel's verdict in all five tiers, benign twins stay allowed.

type sshfp2Row struct {
	id, cwd, command, rule string
	want                   map[string]string
}

var (
	sshfp2Allow = map[string]string{"default": "allow", "permissive": "allow", "strict": "allow", "managed": "allow", "managed-strict": "allow"}
	sshfp2Block = map[string]string{"default": "block", "permissive": "block", "strict": "block", "managed": "block", "managed-strict": "block"}
	sshfp2Warn  = map[string]string{"default": "alert", "permissive": "alert", "strict": "block", "managed": "alert", "managed-strict": "block"}
)

const (
	sshfp2Keys = "persistence.ssh_authorized_keys_command"
	sshfp2Hook = "tamper.agent_hook_config_write"
)

func sshfp2Run(t *testing.T, home string, rows []sshfp2Row) {
	t.Helper()
	for _, row := range rows {
		for _, cell := range []string{"default", "permissive", "strict", "managed", "managed-strict"} {
			posture, managed := cell, false
			switch cell {
			case "managed":
				posture, managed = "default", true
			case "managed-strict":
				posture, managed = "strict", true
			}
			t.Run(fmt.Sprintf("%s %s", cell, row.id), func(t *testing.T) {
				action, rules := shellProtectedFileRoute(t, home, row.cwd, "claudecode", posture, managed, row.command)
				if want := row.want[cell]; action != want {
					t.Fatalf("action = %q (rules %v), want %q", action, rules, want)
				}
				if row.rule != "" && !slices.Contains(rules, row.rule) {
					t.Fatalf("rules = %v, want %s", rules, row.rule)
				}
				if row.rule == "" && len(rules) != 0 {
					t.Fatalf("rules = %v, want none", rules)
				}
			})
		}
	}
}

// GAP-0715: only a bare name or a program in a fixed system folder is a
// plain reader. A program named by any other path, or a file the call
// planted under a reader's name and ran by its path, is an unknown program,
// so the ssh folder it names keeps the rel reading.
func TestGAP0715ReaderStatementNeedsASystemProgram(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	work := filepath.Join(home, "td", "work", "default")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("W", work)
	sshfp2Run(t, home, []sshfp2Row{
		{"R15 ./ls after cd $W", cwd, "cd $W && ./ls ~/.ssh; ssh -V", sshfp2Keys, sshfp2Block},
		{"R16 /tmp/x/ls", cwd, "/tmp/x/ls ~/.ssh; ssh -V", sshfp2Keys, sshfp2Block},
		{"R17 ~/bin/cat", cwd, "~/bin/cat ~/.ssh/authorized_keys; ssh -V", sshfp2Keys, sshfp2Block},
		{"R18 ./cat", cwd, "./cat ~/.ssh/authorized_keys; ssh -V", sshfp2Keys, sshfp2Block},
		{"R58 copied, made executable, run", cwd, "cp notes.txt ls; chmod +x ls; ./ls ~/.ssh/authorized_keys", sshfp2Keys, sshfp2Block},
		{"R59 copied to /tmp and run", cwd, "cp notes.txt /tmp/cat; /tmp/cat ~/.ssh/authorized_keys", sshfp2Keys, sshfp2Block},
		{"R19 pipeline stage by path", cwd, "ls ~/.ssh | ./head; ssh -V", sshfp2Keys, sshfp2Block},
		{"R20 bash body by path", cwd, "bash -c \"./ls ~/.ssh\"; ssh -V", sshfp2Keys, sshfp2Block},
		// Benign twins: a reader a developer really runs.
		{"R53 /usr/bin/ls then ssh -V", cwd, "/usr/bin/ls ~/.ssh; ssh -V", "", sshfp2Allow},
		{"R21 /bin/ls pipeline then ssh -V", cwd, "/bin/ls -la ~/.ssh | /usr/bin/head -5; ssh -V", "", sshfp2Allow},
		{"R22 bare ls then ssh -V", cwd, "ls ~/.ssh; ssh -V", "", sshfp2Allow},
		{"R23 bare cat and head then ssh -G", cwd, "cat ~/.ssh/config | head -5; ssh -G localhost", "", sshfp2Allow},
	})
}

// GAP-0716: a checkout or restore from a named ref or tree brings in the
// files the ref holds, a hook settings file the tree lacks included. Only a
// checkout or restore from the index is limited to the files the tree has or
// the index tracks.
func TestGAP0716NamedSourceCheckoutKeepsTheHookFinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	work := filepath.Join(home, "td", "work", "default")
	repo := filepath.Join(work, "uuid")
	hooked2 := filepath.Join(work, "hooked2")
	hooked3 := filepath.Join(work, "hooked3")
	gone := filepath.Join(work, "gone")
	other := filepath.Join(work, "other")
	for _, dir := range []string{
		filepath.Join(repo, ".git"), filepath.Join(hooked2, ".git"), filepath.Join(hooked2, ".claude"),
		filepath.Join(hooked3, ".git"), filepath.Join(gone, ".git"), filepath.Join(gone, ".claude"),
		filepath.Join(other, ".git"), filepath.Join(other, ".claude"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// gone: the index tracks a settings file that was deleted from the tree;
	// other: the index tracks one source file only.
	sshfp2WriteIndex(t, filepath.Join(gone, ".git", "index"), 2, ".claude/settings.json", "src/main.go")
	sshfp2WriteIndex(t, filepath.Join(other, ".git", "index"), 2, "src/main.go")
	rows := []sshfp2Row{
		{"E71 checkout ref -- . (.claude folder, no file)", hooked2, "git checkout other -- .", sshfp2Hook, sshfp2Warn},
		{"E74 checkout ref -- .", hooked3, "git checkout other -- .", sshfp2Hook, sshfp2Warn},
		{"E77 restore --source=ref .", hooked3, "git restore --source=other .", sshfp2Hook, sshfp2Warn},
		{"E78 restore -s ref -- .", hooked3, "git restore -s other -- .", sshfp2Hook, sshfp2Warn},
		{"E79 checkout origin/main -- .", hooked3, "git checkout origin/main -- .", sshfp2Hook, sshfp2Warn},
		{"E80 checkout FETCH_HEAD -- .", hooked3, "git checkout FETCH_HEAD -- .", sshfp2Hook, sshfp2Warn},
		{"E81 checkout reflog ref -- .", hooked3, "git checkout HEAD@{1} -- .", sshfp2Hook, sshfp2Warn},
		{"E82 checkout -p ref -- .", hooked3, "git checkout -p other -- .", sshfp2Hook, sshfp2Warn},
		{"E87 checkout -b x ref -- .", hooked3, "git checkout -b x other -- .", sshfp2Hook, sshfp2Warn},
		{"E90 restore -sref .", hooked3, "git restore -sother .", sshfp2Hook, sshfp2Warn},
		{"E91 restore --staged --worktree .", hooked3, "git restore --staged --worktree .", sshfp2Hook, sshfp2Warn},
		{"E73 checkout -- . of a tracked deleted settings file", gone, "git checkout -- .", sshfp2Hook, sshfp2Warn},
		{"E92 restore . of a tracked deleted settings file", gone, "git restore .", sshfp2Hook, sshfp2Warn},
		// The index-stage spellings read the same index (rel-1-0-10:GAP-0875 reconcile).
		{"E83i checkout --theirs -- . of a tracked deleted settings file", gone, "git checkout --theirs -- .", sshfp2Hook, sshfp2Warn},
		{"E84i checkout --ours -- . of a tracked deleted settings file", gone, "git checkout --ours -- .", sshfp2Hook, sshfp2Warn},
		{"E85i checkout -m -- . of a tracked deleted settings file", gone, "git checkout -m -- .", sshfp2Hook, sshfp2Warn},
		// What stays named: the settings file or its folder.
		{"E70 checkout ref -- .claude", hooked2, "git checkout other -- .claude", sshfp2Hook, sshfp2Warn},
		{"E75 checkout ref -- .claude (no folder on disk)", hooked3, "git checkout other -- .claude", sshfp2Hook, sshfp2Warn},
		// Benign twins (GAP-0572): the index tracks no hook file.
		{"E42 checkout -- . in a repo with no hook file", repo, "git checkout -- .", "", sshfp2Allow},
		{"E76 checkout -- . (no index file)", hooked3, "git checkout -- .", "", sshfp2Allow},
		{"E93 restore . (no index file)", hooked3, "git restore .", "", sshfp2Allow},
		{"E94 checkout -- . (index tracks other files)", other, "git checkout -- .", "", sshfp2Allow},
		{"E95 restore . (index tracks other files)", other, "git restore .", "", sshfp2Allow},
		{"E96 checkout --theirs -- . (index tracks other files)", other, "git checkout --theirs -- .", "", sshfp2Allow},
		{"E97 checkout -m -- . (index tracks other files)", other, "git checkout -m -- .", "", sshfp2Allow},
	}
	sshfp2Run(t, home, rows)
	_ = cwd
}

// sshfp2WriteIndex writes a git index file of the given version listing the
// names, as git writes one (header, entries padded to 8 bytes, a zero hash).
func sshfp2WriteIndex(t *testing.T, path string, version uint32, names ...string) {
	t.Helper()
	var body bytes.Buffer
	body.WriteString("DIRC")
	_ = binary.Write(&body, binary.BigEndian, version)
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

// GAP-0717: the plain-archive proof reads the member names. A plain file
// that lands on a protected name below the extraction folder (the keys file,
// a shell startup file of the home, a hook settings file) is not a proof
// that the archive makes no link, so a staged copy keeps rel's block. An
// extraction of such an archive from where it lies has no later write for
// the link reading to judge and allows on rel as well; the archive member
// reading that would block it belongs to the extraction-member lane
// (s7/tamper-min).
func TestGAP0717PlainArchiveMemberOnAProtectedNameKeepsTheBlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	downloads, projects := filepath.Join(home, "Downloads"), filepath.Join(home, "projects")
	for _, dir := range []string{downloads, projects} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	reg := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeReg} }
	write := func(file string, names ...string) {
		headers := make([]tar.Header, len(names))
		for i, name := range names {
			headers[i] = reg(name)
		}
		r107WriteTar(t, filepath.Join(downloads, file+".tar.gz"), true, headers...)
		sshfp2WriteZip(t, filepath.Join(downloads, file+".zip"), names...)
	}
	write("keys", ".ssh/authorized_keys")
	write("bashrc", ".bashrc")
	write("hookarch", ".claude/settings.json")
	write("topbashrc", "top/.bashrc")
	write("app", "app/main.go")
	write("plainjson", "app/settings.json", "app/.claude/commands/x.md")
	sshfp2Run(t, home, []sshfp2Row{
		{"S06 cp then tar -C ~ (keys)", cwd, "cp ~/Downloads/keys.tar.gz ~/projects/ && tar xzf ~/projects/keys.tar.gz -C ~", sshfp2Keys, sshfp2Block},
		{"S07 cp then unzip -d ~ (keys)", cwd, "cp ~/Downloads/keys.zip ~/projects/ && unzip -q ~/projects/keys.zip -d ~", sshfp2Keys, sshfp2Block},
		{"S10 cp then unzip (hook settings)", cwd, "cp ~/Downloads/hookarch.zip ~/projects/ && unzip -q ~/projects/hookarch.zip -d ~", sshfp2Keys, sshfp2Block},
		{"S11 cp then tar (hook settings)", cwd, "cp ~/Downloads/hookarch.tar.gz ~/projects/ && tar xzf ~/projects/hookarch.tar.gz -C ~", sshfp2Keys, sshfp2Block},
		{"R60 cp then tar (.bashrc)", cwd, "cp ~/Downloads/bashrc.tar.gz ~/projects/ && tar xzf ~/projects/bashrc.tar.gz -C ~", sshfp2Keys, sshfp2Block},
		{"G11 cp then tar --strip-components drops a folder", cwd, "cp ~/Downloads/topbashrc.tar.gz ~/projects/ && tar xzf ~/projects/topbashrc.tar.gz --strip-components=1 -C ~", sshfp2Keys, sshfp2Block},
		{"G12 cp then unzip -j drops the folder", cwd, "cp ~/Downloads/topbashrc.zip ~/projects/ && unzip -qj ~/projects/topbashrc.zip -d ~", sshfp2Keys, sshfp2Block},
		{"G14 cp then tar -C ~ (hook settings)", cwd, "cp ~/Downloads/hookarch.tar.gz ~/projects/ && tar xzf ~/projects/hookarch.tar.gz -C ~", sshfp2Keys, sshfp2Block},
		// Benign twins: members that land elsewhere.
		{"S01 cp then tar -C ~/projects", cwd, "cp ~/Downloads/app.tar.gz ~/projects/ && tar xzf ~/projects/app.tar.gz -C ~/projects", "", sshfp2Allow},
		{"S15 cp then unzip -d ~/projects", cwd, "cp ~/Downloads/app.zip ~/projects/ && unzip -q ~/projects/app.zip -d ~/projects", "", sshfp2Allow},
		{"G08 tar -C ~ of a folder with a startup file inside", cwd, "tar xzf ~/Downloads/topbashrc.tar.gz -C ~", "", sshfp2Allow},
		{"G09 project settings.json and a .claude commands file", cwd, "tar xzf ~/Downloads/plainjson.tar.gz -C ~/projects", "", sshfp2Allow},
		{"G10 staged zip with the same", cwd, "cp ~/Downloads/plainjson.zip ~/projects/ && unzip -q ~/projects/plainjson.zip -d ~/projects", "", sshfp2Allow},
	})
}

// sshfp2WriteZip writes a zip of regular files with the given names.
func sshfp2WriteZip(t *testing.T, path string, names ...string) {
	t.Helper()
	var body bytes.Buffer
	archive := zip.NewWriter(&body)
	for _, name := range names {
		member, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write([]byte("x\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
