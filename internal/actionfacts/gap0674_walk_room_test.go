package actionfacts

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

func credentialWalkRoomAll() credentialWalkRoom {
	return credentialWalkRoom{candidates: math.MaxInt, work: math.MaxInt}
}

// TestGAP0674WalkRoomKeepsFilesUpToTheTrip is substrate-1:GAP-0674: the walk
// keeps the files the resolve can take and the one that trips its cap, in the
// order they were found, and none after it.
func TestGAP0674WalkRoomKeepsFilesUpToTheTrip(t *testing.T) {
	files := []string{"/a/.env", "/b/.env", "/c/.env", "/d/.env"}
	for _, tc := range []struct {
		name string
		room credentialWalkRoom
		want int
	}{
		{"all fit", credentialWalkRoom{candidates: 4, work: 28}, 4},
		{"candidate cap trips on the third", credentialWalkRoom{candidates: 2, work: 1000}, 3},
		{"work cap trips on the second", credentialWalkRoom{candidates: 100, work: 8}, 2},
		{"nothing left: the first trips", credentialWalkRoom{}, 1},
	} {
		room, kept := tc.room, 0
		for _, f := range files {
			if room.admit(f) {
				kept++
			}
		}
		if kept != tc.want {
			t.Errorf("%s: kept %d files, want %d", tc.name, kept, tc.want)
		}
	}
	// A word the resolve takes nothing for is kept and costs nothing.
	room := credentialWalkRoom{}
	if !room.admit("plain") || !room.admit("") || room.over {
		t.Error("a word without a dot, slash or underscore must be kept and take nothing")
	}
}

// TestGAP0674BoundedCounterLeft: Left is the takes a Counter still allows.
func TestGAP0674BoundedCounterLeft(t *testing.T) {
	var trunc bounded.Truncated
	k := bounded.NewCounter(&trunc, bounded.Time, 10)
	if k.Left() != 10 {
		t.Fatalf("Left = %d, want 10", k.Left())
	}
	k.TakeN(4)
	if k.Left() != 6 {
		t.Fatalf("Left = %d, want 6", k.Left())
	}
	if !k.TakeN(6) || k.Left() != 0 {
		t.Fatalf("a take of exactly what is left must succeed and leave 0, left %d", k.Left())
	}
	if k.Take() || k.Left() != 0 {
		t.Fatalf("a take past max must fail, left %d", k.Left())
	}
}

type walkRoomRecord struct {
	reads []PathFact
	caps  bounded.CapSet
	nil_  bool
}

func resolveWithin(t *testing.T, limits credentialPathLimits, command, cwd, home string) walkRoomRecord {
	t.Helper()
	facts := Analyze(Input{Tool: "exec", Command: command, CWD: cwd, ActiveHome: home})
	l := facts.credentialPaths
	if l == nil {
		return walkRoomRecord{nil_: true}
	}
	rec := resolveCredentialPathReadsWithin(limits, l.words, l.cwd, l.home, l.commands, l.paths)
	if rec == nil {
		return walkRoomRecord{nil_: true}
	}
	return walkRoomRecord{reads: rec.reads, caps: rec.caps}
}

// TestGAP0674WalkRoomDifferential: for each call over a tree of many
// credentials files, under caps from tight to none, the resolve that keeps
// only the files it can take records exactly the reads and caps the resolve
// that keeps every file does. Several folders named by one call exercise the
// resolve that has stopped (the second walk of a call after the cap tripped).
func TestGAP0674WalkRoomDifferential(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 6 {
		for j := range 40 {
			dir := filepath.Join(root, fmt.Sprintf("t%d", i), strings.Repeat("d", 30), fmt.Sprintf("s%d", j))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("K=1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	commands := []string{
		"grep -r KEY t0",
		"grep -r KEY t0 t1 t2",
		"rg --hidden KEY t3 t4",
		"cat t0/dddddddddddddddddddddddddddddd/s1/.env t1",
		"grep -r KEY t5 && grep -r KEY t0",
		"grep -r KEY .",
	}
	var cuts int
	for _, command := range commands {
		for _, candidates := range []int{0, 1, 3, 17, 40, 4096} {
			for _, work := range []int{0, 10, 200, 3000, 20000, 1 << 20} {
				limits := credentialPathLimits{candidates: candidates, work: work, lookups: maxCredentialPathLookups}
				got := resolveWithin(t, limits, command, root, home)
				limits.keepAll = true
				want := resolveWithin(t, limits, command, root, home)
				if got.caps.Any() {
					cuts++
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%q candidates=%d work=%d: record differs\n got %d reads caps %v\nwant %d reads caps %v", command, candidates, work, len(got.reads), got.caps, len(want.reads), want.caps)
				}
			}
		}
	}
	if cuts == 0 {
		t.Fatal("no combination hit a cap: the differential tested nothing")
	}
}

// TestGAP0674ReadStoresItsPathOnce: the spellings of a read that are the same
// text or a part of it share one string's memory, byte for byte as before. A
// Windows read is the value and the working folder joined to it (the record
// kept two paths of 2,400 bytes for each of up to 456 files of a call).
func TestGAP0674ReadStoresItsPathOnce(t *testing.T) {
	value := `C:\work\` + strings.Repeat(`sub\`, 40) + `.env`
	for _, tc := range []struct{ name, value, normalized, resolved string }{
		{"windows: resolved is the folder, a slash and the value", value, value, "/proj/" + value},
		{"posix: all three the same", "/p/q/.env", "/p/q/.env", "/p/q/.env"},
		{"normalized is a part of the value", "/p/q/../r/.env", "/p/r/.env", "/p/r/.env"},
		{"empty spellings stay empty", "", "", ""},
	} {
		fact := PathFact{Value: tc.value, Normalized: tc.normalized, Resolved: tc.resolved}
		fact.storeOnce()
		if fact.Value != tc.value || fact.Normalized != tc.normalized || fact.Resolved != tc.resolved {
			t.Errorf("%s: storeOnce changed a string: %q %q %q", tc.name, fact.Value, fact.Normalized, fact.Resolved)
		}
	}
	fact := PathFact{Value: strings.Clone(value), Normalized: strings.Clone(value), Resolved: "/proj/" + value}
	fact.storeOnce()
	host := unsafe.StringData(fact.Resolved)
	for name, s := range map[string]string{"Value": fact.Value, "Normalized": fact.Normalized} {
		at := uintptr(unsafe.Pointer(unsafe.StringData(s))) - uintptr(unsafe.Pointer(host))
		if at > uintptr(len(fact.Resolved)-len(s)) {
			t.Errorf("%s does not share the memory of Resolved", name)
		}
	}
}
