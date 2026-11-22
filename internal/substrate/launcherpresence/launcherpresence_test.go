// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package launcherpresence

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWriteParseRemove(t *testing.T) {
	dir := t.TempDir()
	remove, err := Write(dir, Record{Command: "run", Connector: "claudecode", Context: "stk"})
	if err != nil {
		t.Fatal(err)
	}
	p := Path(dir, os.Getpid())
	fi, err := os.Stat(p)
	// Windows has no permission bits to read back (the file system reports 0666); the file is private there by its folder ACL.
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("record %v %v", fi, err)
	}
	b, _ := os.ReadFile(p)
	r, ok := Parse(b, os.Getpid())
	if !ok || r.Command != "run" || r.Connector != "claudecode" || !r.Matches(time.Now()) {
		t.Fatalf("parse %+v %v", r, ok)
	}
	if strings.Contains(string(b), "token") || strings.Contains(string(b), "http") {
		t.Errorf("record holds more than a label: %s", b)
	}
	if _, ok := Parse(b, os.Getpid()+1); ok {
		t.Error("a record of another PID was accepted")
	}
	if r.Matches(time.Now().Add(-time.Hour)) {
		t.Error("a reused PID (older process) matched")
	}
	remove()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("record not removed: %v", err)
	}
}

func TestParseRefusesWhatIsNotARecord(t *testing.T) {
	for _, in := range []string{
		`{"pid":7,"started":"2026-11-13T00:00:00Z","command":"rm"}`,
		`{"pid":7,"started":"2026-11-13T00:00:00Z","command":"run","connector":"x\u001b[2J"}`,
		`{"pid":7,"command":"run"}`,
		`not json`,
		`{"pid":7,"started":"2026-11-13T00:00:00Z","command":"run","context":"` + strings.Repeat("a", 5000) + `"}`,
	} {
		if _, ok := Parse([]byte(in), 7); ok {
			t.Errorf("accepted %q", in)
		}
	}
	if _, err := Write(t.TempDir(), Record{Command: "shell"}); err == nil {
		t.Error("an invalid record was written")
	}
}
