// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func readerFacts(command string) Facts {
	return Analyze(Input{Tool: "Bash", Command: command, CWD: "/work"})
}

// Each standard program that reads its file operands records a read fact
// for the ordinary file it is given, and none for the option values.
func TestStandardReadersRecordTheirFileOperands(t *testing.T) {
	for _, row := range []struct {
		name    string
		command string
		reads   []string
		writes  []string
		noRead  []string
	}{
		{name: "tac", command: "tac /work/app.log", reads: []string{"/work/app.log"}},
		{name: "tac separator", command: "tac -s : /work/app.log", reads: []string{"/work/app.log"}, noRead: []string{":"}},
		{name: "nl", command: "nl -ba /work/app.log", reads: []string{"/work/app.log"}},
		{name: "nl number format", command: "nl -n rz -w 3 -s : /work/app.log", reads: []string{"/work/app.log"}, noRead: []string{"rz", "3", ":"}},
		{name: "od", command: "od -An -tx1 /work/blob.bin", reads: []string{"/work/blob.bin"}},
		{name: "od skip", command: "od -j 16 -N 32 /work/blob.bin", reads: []string{"/work/blob.bin"}, noRead: []string{"16", "32"}},
		{name: "strings", command: "strings -n 8 /work/blob.bin", reads: []string{"/work/blob.bin"}, noRead: []string{"8"}},
		{name: "cut", command: "cut -d, -f1 /work/data.csv", reads: []string{"/work/data.csv"}, noRead: []string{",", "1"}},
		{name: "cut separate values", command: "cut -d , -f 1,3 /work/data.csv", reads: []string{"/work/data.csv"}, noRead: []string{",", "1,3"}},
		{name: "sort", command: "sort /work/words.txt", reads: []string{"/work/words.txt"}},
		{name: "sort key", command: "sort -t: -k3 -n /work/passwd.copy", reads: []string{"/work/passwd.copy"}, noRead: []string{"3"}},
		{name: "sort cluster key", command: "sort -rk 2 /work/words.txt", reads: []string{"/work/words.txt"}, noRead: []string{"2"}},
		{name: "sort stable switch", command: "sort -s -r /work/words.txt", reads: []string{"/work/words.txt"}},
		{name: "sort output", command: "sort -o /work/sorted.txt /work/words.txt", reads: []string{"/work/words.txt"}, writes: []string{"/work/sorted.txt"}, noRead: []string{"/work/sorted.txt"}},
		{name: "sort long output", command: "sort --output=/work/sorted.txt /work/words.txt", reads: []string{"/work/words.txt"}, writes: []string{"/work/sorted.txt"}},
		{name: "sort files0-from", command: "sort --files0-from=/work/names.lst", reads: []string{"/work/names.lst"}},
		{name: "hexdump", command: "hexdump -C /work/blob.bin", reads: []string{"/work/blob.bin"}},
		{name: "hexdump format file", command: "hexdump -n 16 -f /work/fmt.txt /work/blob.bin", reads: []string{"/work/fmt.txt", "/work/blob.bin"}, noRead: []string{"16"}},
		{name: "diff", command: "diff /work/a.txt /work/b.txt", reads: []string{"/work/a.txt", "/work/b.txt"}},
		{name: "diff option values", command: "diff -U 3 -x skip /work/a.txt /work/b.txt", reads: []string{"/work/a.txt", "/work/b.txt"}, noRead: []string{"3", "skip"}},
		{name: "diff from-file", command: "diff --from-file=/work/a.txt /work/b.txt", reads: []string{"/work/a.txt", "/work/b.txt"}},
		{name: "tar members around -C", command: "tar cf /tmp/out.tar -C /work src", reads: []string{"src"}, writes: []string{"/tmp/out.tar"}, noRead: []string{"/work", "-C"}},
		{name: "tar long directory", command: "tar -cf /tmp/out.tar --directory=/work src", writes: []string{"/tmp/out.tar"}, noRead: []string{"--directory=/work"}},
		{name: "xxd", command: "xxd /work/blob.bin", reads: []string{"/work/blob.bin"}},
		{name: "xargs -a", command: "xargs -a /work/files.lst echo", reads: []string{"/work/files.lst"}},
		{name: "xargs --arg-file", command: "xargs -n 1 --arg-file=/work/files.lst ls", reads: []string{"/work/files.lst"}, noRead: []string{"1"}},
		{name: "tar -c", command: "tar -czf /tmp/out.tgz /work/src", reads: []string{"/work/src"}, writes: []string{"/tmp/out.tgz"}},
		{name: "tar c traditional", command: "tar cf /tmp/out.tar /work/src /work/notes.txt", reads: []string{"/work/src", "/work/notes.txt"}, writes: []string{"/tmp/out.tar"}},
		{name: "zip", command: "zip -r /tmp/out.zip /work/src", reads: []string{"/work/src"}, writes: []string{"/tmp/out.zip"}},
		{name: "rsync local", command: "rsync -a /work/src/ /tmp/dst/", reads: []string{"/work/src/"}, writes: []string{"/tmp/dst/"}},
		// The pass-through wrappers: the wrapped program is classified.
		{name: "nice", command: "nice -n 5 tac /work/app.log", reads: []string{"/work/app.log"}},
		{name: "nice historical", command: "nice -10 sort /work/words.txt", reads: []string{"/work/words.txt"}},
		{name: "time", command: "/usr/bin/time -p cut -f1 /work/data.tsv", reads: []string{"/work/data.tsv"}},
		{name: "timeout", command: "timeout 30 od -c /work/blob.bin", reads: []string{"/work/blob.bin"}},
		{name: "timeout options", command: "timeout -s KILL -k 5 2.5m strings /work/blob.bin", reads: []string{"/work/blob.bin"}},
		{name: "nohup", command: "nohup nl /work/app.log", reads: []string{"/work/app.log"}},
		{name: "env options", command: "env -i -u HOME hexdump -C /work/blob.bin", reads: []string{"/work/blob.bin"}},
		{name: "wrappers nest", command: "nohup nice timeout 9 env tac /work/app.log", reads: []string{"/work/app.log"}},
		{name: "wrapped cat", command: "timeout 5 cat /work/app.log", reads: []string{"/work/app.log"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			facts := readerFacts(row.command)
			for _, want := range row.reads {
				if !hasPathAccessValue(facts.Paths, PathAccessRead, want) {
					t.Errorf("%q: no read fact for %q in %+v", row.command, want, facts.Paths)
				}
			}
			for _, want := range row.writes {
				if !hasPathAccessValue(facts.Paths, PathAccessWrite, want) {
					t.Errorf("%q: no write fact for %q in %+v", row.command, want, facts.Paths)
				}
			}
			for _, not := range row.noRead {
				if hasPathAccessValue(facts.Paths, PathAccessRead, not) {
					t.Errorf("%q: %q is not a file it reads: %+v", row.command, not, facts.Paths)
				}
			}
		})
	}
}

// A stdin-only run has no file to record, and an option that starts a
// program keeps the parse partial.
func TestStandardReadersStaySafeOnOddArguments(t *testing.T) {
	for _, command := range []string{
		"sort --compress-program=/work/helper /work/words.txt",
	} {
		if facts := readerFacts(command); facts.Authoritative() {
			t.Errorf("%q: a program started by sort must keep the parse partial", command)
		}
	}
	for _, command := range []string{"sort -r", "cut -d, -f1", "tac -", "strings -"} {
		for _, path := range readerFacts(command).Paths {
			if path.Access == PathAccessRead {
				t.Errorf("%q: unexpected read fact %+v", command, path)
			}
		}
	}
}

// env VAR=value stays opaque (TestParsePOSIXContextChangingWrappersFailClosed):
// the wrapped program is not classified, so no read is recorded.
func TestEnvWrapperWithAssignmentStaysOpaque(t *testing.T) {
	for _, command := range []string{
		"env LANG=C tac /work/app.log",
		"env PATH=/tmp/bin tac /work/app.log",
	} {
		facts := readerFacts(command)
		if hasPathAccessValue(facts.Paths, PathAccessRead, "/work/app.log") || facts.Authoritative() {
			t.Errorf("%q: want an opaque wrapper, got authoritative=%t paths=%+v",
				command, facts.Authoritative(), facts.Paths)
		}
	}
}

func TestStaticPOSIXWrapperArgvPassThroughWrappers(t *testing.T) {
	for _, row := range []struct {
		argv      []string
		program   string
		want      []string
		uncertain bool
	}{
		{[]string{"nice", "tac", "f"}, "nice", []string{"tac", "f"}, false},
		{[]string{"nice", "-n", "5", "tac", "f"}, "nice", []string{"tac", "f"}, false},
		{[]string{"nice", "-n5", "tac", "f"}, "nice", []string{"tac", "f"}, false},
		{[]string{"nice", "--adjustment=5", "--", "tac", "f"}, "nice", []string{"tac", "f"}, false},
		{[]string{"nice", "-5", "tac", "f"}, "nice", []string{"tac", "f"}, false},
		{[]string{"nice", "-x", "tac"}, "nice", nil, true},
		{[]string{"nice", "-n"}, "nice", nil, true},
		{[]string{"time", "-p", "tac", "f"}, "time", []string{"tac", "f"}, false},
		{[]string{"time", "-f", "%e", "tac", "f"}, "time", []string{"tac", "f"}, false},
		{[]string{"time", "-o", "r.txt", "tac"}, "time", nil, true},
		{[]string{"timeout", "5", "tac", "f"}, "timeout", []string{"tac", "f"}, false},
		{[]string{"timeout", "-s", "KILL", "1.5h", "tac", "f"}, "timeout", []string{"tac", "f"}, false},
		{[]string{"timeout", "--kill-after=3", "10", "tac"}, "timeout", []string{"tac"}, false},
		{[]string{"timeout", "soon", "tac"}, "timeout", nil, true},
		{[]string{"timeout", "5"}, "timeout", nil, false},
		{[]string{"nohup", "tac", "f"}, "nohup", []string{"tac", "f"}, false},
		{[]string{"nohup", "--", "tac", "f"}, "nohup", []string{"tac", "f"}, false},
		{[]string{"nohup", "-x", "tac"}, "nohup", nil, true},
		{[]string{"env", "A=1", "tac"}, "env", nil, true},
		{[]string{"env", "-i", "-u", "HOME", "tac", "f"}, "env", []string{"tac", "f"}, false},
	} {
		got, ok, uncertain := staticPOSIXWrapperArgv(row.argv, row.program)
		if uncertain != row.uncertain || ok != (row.want != nil) || len(got) != len(row.want) {
			t.Errorf("staticPOSIXWrapperArgv(%q) = %q, %t, %t; want %q uncertain %t",
				row.argv, got, ok, uncertain, row.want, row.uncertain)
			continue
		}
		for i := range got {
			if got[i] != row.want[i] {
				t.Errorf("staticPOSIXWrapperArgv(%q) = %q, want %q", row.argv, got, row.want)
				break
			}
		}
	}
}
