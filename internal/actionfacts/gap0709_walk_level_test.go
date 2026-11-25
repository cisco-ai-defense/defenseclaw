package actionfacts

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The hook-cost probe's tree (substrate-1:GAP-0709): 64 folders of 4,081
// folders, so the third level does not fit in the walk's 4,096-folder
// bound. The walk reads the two levels that fit (65 folders, 4,146
// entries) and is cut there, charged the whole folder bound; it no longer
// reads 4,031 folders of the third level, which was about 7 ms on every
// grep -r or rg call in that tree. The .env at the top counts, and the cut
// adds the file-unknown read as before.
func TestGAP0709WalkSkipsTheLevelPastTheBound(t *testing.T) {
	root := t.TempDir()
	for i := range 4081 {
		folder := filepath.Join(root, "d"+strconv.Itoa(i%64), "e"+strconv.Itoa(i))
		if err := os.MkdirAll(folder, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(folder, "f.go"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{".env", "d1/e1/.env", "d2/e2/.npmrc"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(file)), []byte("KEY=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	walk := credentialPathWalk(credentialWalkBudgetUnbounded(), root, root, credentialWalkFilter{}, credentialPathWalkBounds, credentialWalkRoomAll())
	if want := (credentialPathWalkLimits{folders: 4096, entries: 4146, lookups: 1}); walk.used != want || !walk.cut {
		t.Fatalf("walk used %+v cut %v, want %+v cut true: the level past the bound was read", walk.used, walk.cut, want)
	}
	if want := []string{filepath.Join(root, ".env")}; !slices.Equal(walk.found, want) {
		t.Fatalf("walk found %v, want %v", walk.found, want)
	}
	for _, command := range []string{"grep -rn TODO .", "rg TODO", "rg --hidden TODO", "grep -r KEY . d1"} {
		facts := Analyze(Input{Tool: "exec", Command: command, CWD: root, ActiveHome: t.TempDir()})
		if caps := facts.CredentialPathReadCaps(context.Background()); caps.Any() {
			t.Fatalf("%s: a cut walk is a cap of the resolve: %v", command, caps)
		}
		if !slices.ContainsFunc(facts.CredentialPathReads(), func(p PathFact) bool { return p.Value == "" }) {
			t.Fatalf("%s: reads %v, want the file-unknown read of the cut", command, facts.CredentialPathReads())
		}
	}
}

// TestGAP0709ParseWalksWhenTheRecordIsRead is substrate-1:GAP-0709: a parse
// resolves its credentials-file reads, and walks the folders its recursive
// searches name, only when the record is first read. The hook parses one
// call about fifteen times and reads one record, so the other parses walk
// nothing: a .env made after the parse and before the read is found. At
// 02e880d943 the parse walked at once and missed it.
func TestGAP0709ParseWalksWhenTheRecordIsRead(t *testing.T) {
	for _, command := range []string{"grep -rn TODO .", "rg -uu TODO"} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
			t.Fatal(err)
		}
		facts := Analyze(Input{Tool: "exec", Command: command, CWD: dir, ActiveHome: t.TempDir()})
		copied := facts
		if err := os.WriteFile(filepath.Join(dir, "src", ".env"), []byte("KEY=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, read := range copied.CredentialPathReads() {
			found = found || strings.HasSuffix(filepath.ToSlash(read.Resolved), "/src/.env") || strings.HasSuffix(filepath.ToSlash(read.Value), "src/.env")
		}
		if !found {
			t.Fatalf("%s: the parse walked before its record was read: %+v", command, copied.CredentialPathReads())
		}
		if got, again := facts.CredentialPathReads(), copied.CredentialPathReads(); !slices.Equal(got, again) {
			t.Fatalf("%s: copies of one parse disagree: %v and %v", command, got, again)
		}
	}
}
