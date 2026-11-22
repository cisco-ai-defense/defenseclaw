// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// stateGlobTwinText is the reading StateGlobTwin gives, called through
// reflect so the test reads the same at the base (two results) and with the
// bound result (three).
func stateGlobTwinText(command, home string) string {
	return reflect.ValueOf(StateGlobTwin).Call([]reflect.Value{reflect.ValueOf(command), reflect.ValueOf(home)})[0].String()
}

// GAP-1726: decoy patterns over one large state folder used up the work of
// the command (each pattern listed the folder again), so a later state
// pattern had no reading. A folder is listed and charged once per command.
func TestStateGlobDecoysDoNotSpendTheStatePattern(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		home = filepath.ToSlash(home)
	}
	big := filepath.Join(home, ".defenseclaw", "big")
	if err := os.MkdirAll(big, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4000; i++ {
		if err := os.WriteFile(filepath.Join(big, fmt.Sprintf("n%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := "ls " + strings.Repeat("~/.defenseclaw/big/zz* ", 140) + "; cp a.txt ~/.defenseclaw/conf*.yaml"
	want := home + "/.defenseclaw/config.yaml"
	if got := stateGlobTwinText(command, home); !strings.Contains(got, want) {
		t.Fatalf("the state pattern behind 140 decoys is not read: twin %.120q... has no %s", got, want)
	}
}

// Work that still runs out (decoys over many folders) records the counted
// work cap, so the call is TRUNCATED instead of judged on its literal words
// (GAP-1726), and a pattern past the match cap keeps its first matches and
// records bounded.Items (GAP-1017).
func TestStateGlobReadingRecordsItsCaps(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		home = filepath.ToSlash(home)
	}
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(state, dir), 0o700); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8; i++ {
			if err := os.WriteFile(filepath.Join(state, dir, fmt.Sprintf("n%d", i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := 0; i < maxStateGlobMatches+6; i++ {
		if err := os.WriteFile(filepath.Join(state, fmt.Sprintf("m%03d.yaml", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var trunc bounded.Truncated
	reading := stateGlobReading{home: home, trunc: &trunc, work: bounded.NewCounter(&trunc, bounded.Time, 12)}
	if _, complete := reading.matches(home + "/.defenseclaw/a/*"); !complete {
		t.Fatal("the first folder (9 units) is within 12 units")
	}
	if _, complete := reading.matches(home + "/.defenseclaw/a/n*"); !complete {
		t.Fatal("a folder already listed costs nothing again")
	}
	if _, complete := reading.matches(home + "/.defenseclaw/b/*"); complete {
		t.Fatal("the second folder (18 units in all) is past 12 units")
	}
	if set := trunc.Set(&reading.work); !set.Has(bounded.Time) {
		t.Fatalf("work cap not recorded: %v", set.Reason())
	}

	var trunc2 bounded.Truncated
	reading = stateGlobReading{home: home, trunc: &trunc2, work: bounded.NewCounter(&trunc2, bounded.Time, maxStateGlobWork)}
	matches, _ := reading.matches(home + "/.defenseclaw/m*.yaml")
	if len(matches) != maxStateGlobMatches {
		t.Fatalf("%d matches read, want the first %d", len(matches), maxStateGlobMatches)
	}
	if set := trunc2.Set(&reading.work); !set.Has(bounded.Items) {
		t.Fatalf("match cap not recorded: %v", set.Reason())
	}
}
