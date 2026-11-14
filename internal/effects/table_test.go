// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The permanent probe table (GAP-0137). Every probe from the Opus 5.5 reviews
// (all ids ever logged, the review-6 confirmation hunt and the review-7 set) is
// one row: an id, the options and call it runs under, and the real target it
// mutates. checkRow is the single place a row is judged, so a row can not be
// added without a frozen verdict and a row can not be skipped:
//
//  1. the verdict (fully-known status + the set of KNOWN mutation targets) must
//     equal the one frozen in testdata/probe_golden.tsv -- a row with no frozen
//     verdict fails, and so does a frozen verdict no row produced (TestMain);
//  2. the invariant runs on EVERY row that names a real target:
//     real == "-"  the target is dynamic: the call must not be fully known;
//     real == path a fully known call must carry a KNOWN mutation (write,
//     append, delete, link or permission change -- a read at
//     the path does not count) at exactly that path.
//
// Rows are regenerated deliberately with S7_GOLDEN_UPDATE=1 and the diff is
// reviewed; nothing regenerates silently.

const dynamicTarget = "-"

// row is one table row.
type row struct {
	id   string
	o    Options
	call Call
	real string
}

func shellRow(id string, o Options, wd, cmd, real string) row {
	return row{id: id, o: o, call: Call{Surface: SurfaceShell, Command: cmd, Workdir: wd}, real: real}
}

func isMutation(k Kind) bool {
	switch k {
	case KindWrite, KindAppend, KindDelete, KindLink, KindPermissionChange:
		return true
	}
	return false
}

type seenRow struct {
	input   string
	verdict string
}

var (
	rowMu   sync.Mutex
	rowSeen = map[string]seenRow{}

	goldenOnce sync.Once
	golden     = map[string]string{}
	updateMode = os.Getenv("S7_GOLDEN_UPDATE") == "1"
)

func loadGolden() {
	goldenOnce.Do(func() {
		f, err := os.Open("testdata/probe_golden.tsv")
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if i := strings.IndexByte(line, '\t'); i > 0 {
				golden[line[:i]] = line[i+1:]
			}
		}
	})
}

// checkRow runs one table row and judges it. It returns the result so a caller
// with extra assertions can use it.
func checkRow(t *testing.T, id string, o Options, c Call, real string) Result {
	t.Helper()
	loadGolden()
	r := Extract(c, o)
	v := raVerdict(r)
	input := c.Command + "\x00" + strings.Join(c.Argv, " ") + "\x00" + string(c.Args) + "\x00" + c.Workdir + "\x00" + c.Tool
	rowMu.Lock()
	if prev, ok := rowSeen[id]; ok && prev.input != input {
		t.Errorf("%s: two rows share this id with different inputs", id)
	}
	rowSeen[id] = seenRow{input: input, verdict: v}
	rowMu.Unlock()

	switch real {
	case "":
	case dynamicTarget:
		if r.FullyKnown() {
			t.Errorf("%s: fully known but its real target is dynamic\n%s", id, fmtRes(r))
		}
	default:
		if r.FullyKnown() {
			want := real
			subtree := strings.HasSuffix(want, "/**")
			want = strings.TrimSuffix(want, "/**")
			fold := func(s string) string {
				if o.Flavor == FlavorWindows || o.CaseInsensitive {
					return strings.ToLower(s)
				}
				return s
			}
			want = fold(want)
			hit := false
			for _, e := range r.Effects {
				if !isMutation(e.Kind) || e.TargetState != TargetStateKnown || e.Target.Type != TargetPath {
					continue
				}
				if subtree && !e.Target.Subtree {
					continue // a tree write is only the subtree form
				}
				// the lexical name (a link's own path) or the canonical key.
				if e.Target.Key() == want || fold(e.Target.Path) == want {
					hit = true
				}
			}
			if !hit {
				t.Errorf("%s: fully known but no KNOWN mutation (write/append/delete/link/perm) at the real target %q\n%s", id, want, fmtRes(r))
			}
		}
	}

	if !updateMode {
		want, ok := golden[id]
		switch {
		case !ok:
			t.Errorf("%s: no frozen verdict in testdata/probe_golden.tsv (run with S7_GOLDEN_UPDATE=1 and review the diff); got %q", id, v)
		case v != want:
			t.Errorf("%s: verdict changed: got %q want %q\n%s", id, v, want, fmtRes(r))
		}
	}
	return r
}

// TestMain checks, after a full run, that every frozen verdict was produced by
// some row (a deleted row can not hide), and writes the golden file in update
// mode. A run filtered with -run skips both.
func TestMain(m *testing.M) {
	code := m.Run()
	if f := flag.Lookup("test.run"); f != nil && f.Value.String() != "" {
		os.Exit(code)
	}
	if flag.Lookup("test.short") != nil && flag.Lookup("test.short").Value.String() == "true" {
		os.Exit(code)
	}
	loadGolden()
	rowMu.Lock()
	defer rowMu.Unlock()
	if updateMode {
		ids := make([]string, 0, len(rowSeen))
		for id := range rowSeen {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var b strings.Builder
		for _, id := range ids {
			fmt.Fprintf(&b, "%s\t%s\n", id, rowSeen[id].verdict)
		}
		if err := os.MkdirAll("testdata", 0o755); err == nil {
			_ = os.WriteFile("testdata/probe_golden.tsv", []byte(b.String()), 0o644)
		}
		fmt.Printf("probe table: wrote %d frozen verdicts\n", len(ids))
		os.Exit(code)
	}
	if code == 0 {
		var missing []string
		for id := range golden {
			if _, ok := rowSeen[id]; !ok {
				missing = append(missing, id)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			fmt.Printf("probe table: %d frozen verdicts have no row (first: %q)\n", len(missing), missing[0])
			code = 1
		}
	}
	os.Exit(code)
}
