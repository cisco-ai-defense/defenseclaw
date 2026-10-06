// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// testScope asks for a content file, a skills folder listed three deep, a
// project searched for package.json and an executable lookup.
func testScope() *collectScope {
	s := newCollectScope()
	s.exact["/sandbox/.dccert/mcp.json"], s.content["/sandbox/.dccert/mcp.json"] = true, true
	s.exact["/sandbox/.bash_history"], s.content["/sandbox/.bash_history"] = true, true
	s.dirs["/sandbox/.dccert/skills"] = 3
	s.walks = []string{"/sandbox/work/repo"}
	s.manifests["package.json"] = true
	s.exeDirs["/sandbox/.local/bin"], s.binaries["dccert"] = true, true
	return s
}

func answerOf(lines ...string) []byte {
	return []byte(collectSchema + "\n" + strings.Join(lines, "\n") + "\n")
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseCollectionKeepsWhatWasAsked(t *testing.T) {
	out := answerOf(
		"T 100 1700000000",
		"P 42 1 1000 500 S", "Pc 42 dccert", "Pa 42 /sandbox/.local/bin/dccert", "Pt 42 /sandbox/.local/lib/dccert/cli.js",
		"L /proc/42 exe /usr/bin/node", "V DCCERT_MARKER", "V PATH",
		"X 10 1700000001.5 /sandbox/.local/bin/dccert",
		"E f 52 1700000002 /sandbox/.dccert/mcp.json",
		"F /sandbox/.dccert/mcp.json", b64(`{"mcpServers":{"dccert-marker":{}}}`),
		"E d 0 1700000003 /sandbox/.dccert/skills", "E d 0 1700000004 /sandbox/.dccert/skills/one",
		"E f 3 1700000005 /sandbox/.dccert/skills/one/sub/SKILL.md",
		"E f 20 1700000006 /sandbox/work/repo/node_modules/x/package.json",
		collectEnd,
	)
	c, err := parseCollection(out, false, testScope(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Ended || c.Refused != 0 || len(c.Problems) != 0 {
		t.Fatalf("ended=%v refused=%d problems=%v, want a clean answer", c.Ended, c.Refused, c.Problems)
	}
	if len(c.Processes) != 1 || c.Processes[0].Exe != "/usr/bin/node" || c.Processes[0].Argv0Target != "/sandbox/.local/lib/dccert/cli.js" {
		t.Fatalf("processes = %+v", c.Processes)
	}
	if got := c.started(c.Processes[0]); !got.Equal(time.Unix(1700000005, 0).UTC()) {
		t.Fatalf("start = %v, want boot + 500 ticks", got)
	}
	if len(c.EnvNames) != 2 || c.Executables["dccert"].Path != "/sandbox/.local/bin/dccert" || len(c.Entries) != 5 {
		t.Fatalf("env=%v exes=%v entries=%v", c.EnvNames, c.Executables, c.Entries)
	}
	if string(c.Contents["/sandbox/.dccert/mcp.json"]) != `{"mcpServers":{"dccert-marker":{}}}` {
		t.Fatalf("contents = %q", c.Contents)
	}
}

// Paths the sandbox names are refused unless absolute, clean, printable,
// under the sandbox's roots and within what was asked.
func TestParseCollectionRefusesHostilePaths(t *testing.T) {
	hostile := []string{
		"E f 1 1 /sandbox/.dccert/skills/../../../etc/passwd",
		"E f 1 1 /sandbox/.dccert/skills/./x",
		"E f 1 1 /sandbox//.dccert/skills/x",
		"E f 1 1 /sandbox/.dccert/skills/x/",
		"E f 1 1 sandbox/.dccert/skills/x",
		"E f 1 1 /etc/passwd",
		"E f 1 1 /sandbox/.ssh/id_rsa",
		"E f 1 1 /sandbox/.dccert/skills/a\x01b",
		"E f 1 1 /sandbox/.dccert/skills/a\x1b[31mb",
		"E f 1 1 /sandbox/.dccert/skills/a\x7fb",
		"E f 1 1 /sandbox/.dccert/skills/a\u0085b",
		"E f 1 1 /sandbox/.dccert/skills/\xff\xfe",
		"E f 1 1 /sandbox/.dccert/skills/" + strings.Repeat("a", 256),
		"E f 1 1 /sandbox/.dccert/skills/" + strings.Repeat("a/", 2100) + "z",
		"E f 1 1 /sandbox/.dccert/skills/a/b/c/d",
		"E f -1 1 /sandbox/.dccert/skills/neg",
		"E f 1 NaN /sandbox/.dccert/skills/nan",
		"E f 1 1e40 /sandbox/.dccert/skills/far",
		"E fx 1 1 /sandbox/.dccert/skills/type",
		"E f 1 1",
		"X 1 1 /sandbox/.local/bin/other",
		"X 1 1 /usr/bin/dccert",
		"F /sandbox/.dccert/skills/one", b64("not asked for"),
		"F /etc/shadow", b64("not asked for"),
	}
	c, err := parseCollection(answerOf(append(hostile, collectEnd)...), false, testScope(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 0 || len(c.Executables) != 0 || len(c.Contents) != 0 {
		t.Fatalf("entries=%v exes=%v contents=%v, want every hostile record refused", c.Entries, c.Executables, c.Contents)
	}
	if want := len(hostile) - 2; c.Refused != want {
		t.Fatalf("refused = %d, want %d", c.Refused, want)
	}
}

func TestParseCollectionBoundsContent(t *testing.T) {
	c, err := parseCollection(answerOf(
		"F /sandbox/.dccert/mcp.json", b64(strings.Repeat("x", 2048)),
		"F /sandbox/.bash_history", "not base64 at all!",
		collectEnd,
	), false, testScope(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Contents) != 0 || c.Refused != 2 {
		t.Fatalf("contents=%d refused=%d, want the oversize and the malformed file refused", len(c.Contents), c.Refused)
	}
	if !strings.Contains(strings.Join(c.Problems, ";"), "over 1024 bytes") {
		t.Fatalf("problems = %v, want the oversize file named", c.Problems)
	}
	// A file listed over the bound, whose content the collector left out,
	// makes the answer partial too.
	c, err = parseCollection(answerOf("E f 4096 1 /sandbox/.dccert/mcp.json", collectEnd), false, testScope(), 1024)
	if err != nil || !strings.Contains(strings.Join(c.Problems, ";"), "1 file(s) over 1024 bytes were not read") {
		t.Fatalf("problems = %v, %v", c.Problems, err)
	}
	// A content line cut off by the stream's end is refused, and the cut
	// answer is reported.
	c, err = parseCollection([]byte(collectSchema+"\nF /sandbox/.dccert/mcp.json\n"+b64("abc")[:2]), true, testScope(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Contents) != 0 || !strings.Contains(strings.Join(c.Problems, ";"), "cut at") {
		t.Fatalf("contents=%v problems=%v", c.Contents, c.Problems)
	}
}

// A folder of 100,000 entries stops at the entry bound, quickly.
func TestParseCollectionCapsAHundredThousandEntries(t *testing.T) {
	var b strings.Builder
	b.WriteString(collectSchema + "\nE d 0 1 /sandbox/.dccert/skills\n")
	for i := range 100_000 {
		fmt.Fprintf(&b, "E f 0 1 /sandbox/.dccert/skills/s%06d\n", i)
	}
	b.WriteString(collectEnd + "\n")
	start := time.Now()
	c, err := parseCollection([]byte(b.String()), false, testScope(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != collectMaxEntries || !strings.Contains(strings.Join(c.Problems, ";"), "more than") {
		t.Fatalf("entries = %d problems = %v, want the bound of %d", len(c.Entries), c.Problems, collectMaxEntries)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("parse took %s", took)
	}
	root := filepath.Join(t.TempDir(), "root")
	n, err := writeCollectedTree(root, c)
	if err != nil || n != collectMaxEntries {
		t.Fatalf("wrote %d, %v, want %d", n, err, collectMaxEntries)
	}
}

// /proc lines the workload shapes (its argv, its comm) cannot forge a
// process or its fields.
func TestParseCollectionReadsHostileProcessLines(t *testing.T) {
	c, err := parseCollection(answerOf(
		"T 1000 1700000000",
		"T 100 -5",
		"P 7 1 1000 10 S",
		"P 7 1 1000 10 S",
		"P x 1 1000 10 S", "P -3 1 1000 10 S", "P 8 1 1000 10 SS", "P 9 1 1000 10 1", "P 10 1 1000", "P 11 1 1000 10 S extra",
		"Pc 7 evil\x1b[2Jname\x07", "Pc 99 orphan",
		"Pa 7 "+strings.Repeat("a", 1000),
		"Pa 7 two", "Pa 7 three", "Pa 7 4", "Pa 7 5", "Pa 7 6", "Pa 7 7", "Pa 7 8", "Pa 7 9", "Pa 7 10", "Pa 7 11", "Pa 7 12", "Pa 7 13", "Pa 7 14", "Pa 7 15", "Pa 7 16", "Pa 7 17",
		"L /proc/7x exe /bin/sh", "L /proc/../7 exe /bin/sh", "L /proc/123 exe /bin/sh", "L /proc/7 exe relative/path", "L /proc/7 cwd /sandbox/work",
		"V 1BAD", "V BAD-NAME", "V GOOD_NAME", "V GOOD_NAME",
		"Z unknown",
		collectEnd,
		"P 12 1 1000 10 S",
	), false, testScope(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Processes) != 1 || !c.Boot.IsZero() {
		t.Fatalf("processes = %+v boot = %v, want only pid 7 and no boot time", c.Processes, c.Boot)
	}
	p := c.Processes[0]
	if strings.ContainsAny(p.Comm, "\x1b\x07") || len(p.Args) != collectMaxArgs || len(p.Args[0]) != collectMaxArgBytes {
		t.Fatalf("process = %+v, want display-safe comm and bounded args", p)
	}
	if p.Exe != "" || p.Cwd != "/sandbox/work" {
		t.Fatalf("exe=%q cwd=%q, want only the clean link", p.Exe, p.Cwd)
	}
	if len(c.EnvNames) != 1 || c.EnvNames[0] != "GOOD_NAME" {
		t.Fatalf("env = %v", c.EnvNames)
	}
	if c.Ended || !strings.Contains(strings.Join(c.Problems, ";"), "after its end") {
		t.Fatalf("ended=%v problems=%v, want a record after the end refused", c.Ended, c.Problems)
	}
}

func TestParseCollectionRefusesAForeignAnswer(t *testing.T) {
	for _, out := range []string{"", "hello\nend\n", "dccollect 2\nend\n"} {
		if _, err := parseCollection([]byte(out), false, testScope(), 1024); err == nil {
			t.Fatalf("answer %q accepted", out)
		}
	}
	c, err := parseCollection([]byte(collectSchema+"\n"), false, testScope(), 1024)
	if err != nil || !strings.Contains(strings.Join(c.Problems, ";"), "cut short") {
		t.Fatalf("problems = %v, %v, want an answer without its end reported", c, err)
	}
}

// The tree holds owner-only folders and regular files only: a link, a FIFO
// or a device the sandbox reports is never made, and nothing is written
// through what was at the tree's place.
func TestWriteCollectedTreeWritesOnlyPrivateRegularFiles(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	must(t, os.Mkdir(outside, 0o700))
	writeFile(t, filepath.Join(outside, "keep"), "dccert-block-marker")
	root := filepath.Join(base, "root")
	must(t, os.Symlink(outside, root))
	when := time.Unix(1700000000, 0).UTC()
	c := &collection{Contents: map[string][]byte{"/sandbox/.dccert/mcp.json": []byte("{}")}, Executables: map[string]collectedEntry{}}
	c.Entries = []collectedEntry{
		{Path: "/sandbox/.dccert", Type: 'd', MTime: when},
		{Path: "/sandbox/.dccert/mcp.json", Type: 'f', MTime: when},
		{Path: "/sandbox/.dccert/link", Type: 'l', MTime: when},
		{Path: "/sandbox/.dccert/fifo", Type: 'p', MTime: when},
		{Path: "/sandbox/.dccert/dev", Type: 'c', MTime: when},
		{Path: "/sandbox/.dccert/mcp.json/child", Type: 'f', MTime: when},
	}
	n, err := writeCollectedTree(root, c)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || c.Refused != 3 {
		t.Fatalf("wrote %d refused %d, want the folder, the file and the link's name written", n, c.Refused)
	}
	if data, err := os.ReadFile(filepath.Join(outside, "keep")); err != nil || string(data) != "dccert-block-marker" {
		t.Fatalf("the link's target changed: %q, %v", data, err)
	}
	err = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if info.Mode().Perm() != 0o700 {
				t.Errorf("%s mode %o", p, info.Mode().Perm())
			}
		case info.Mode().IsRegular():
			if info.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %o", p, info.Mode().Perm())
			}
		default:
			t.Errorf("%s is %v, not a regular file or folder", p, info.Mode().Type())
		}
		return nil
	})
	must(t, err)
	info, err := os.Lstat(filepath.Join(root, "sandbox", ".dccert", "mcp.json"))
	if err != nil || !info.ModTime().Equal(when) {
		t.Fatalf("mtime = %v, %v, want %v", info, err, when)
	}
	if info, err := os.Lstat(filepath.Join(root, "sandbox", ".dccert")); err != nil || !info.ModTime().Equal(when) {
		t.Fatalf("folder mtime = %v, %v", info, err)
	}
}

// collectArgv runs the script in an empty environment with the image's
// tools: nothing the workload plants on PATH runs.
func TestCollectArgvRunsInAnEmptyEnvironment(t *testing.T) {
	argv := collectArgv("discover", 1024, []string{"S", "/sandbox/x"})
	want := []string{"/usr/bin/env", "-i", "PATH=/usr/bin:/bin"}
	for i, w := range want {
		if argv[i] != w {
			t.Fatalf("argv = %q", argv)
		}
	}
	if argv[4] != "LC_ALL=C" || argv[5] != "/bin/bash" || argv[6] != "-p" || argv[len(argv)-2] != "S" {
		t.Fatalf("argv = %q", argv)
	}
}

// The script itself, against a real tree on this machine (GNU tools, as in
// the sandbox image): FIFOs never hold it, links, newlines in names and
// folder sizes are bounded, and its answer parses.
func TestCollectScriptReadsATreeWithoutHanging(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the collector runs in Linux sandboxes; it needs GNU find, head -z and /proc")
	}
	for _, tool := range []string{"/bin/bash", "/usr/bin/find", "/usr/bin/base64", "/usr/bin/head", "/usr/bin/tail", "/usr/bin/tr"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("%s is missing", tool)
		}
	}
	top := t.TempDir()
	home := filepath.Join(top, "home")
	skills := filepath.Join(home, ".dccert", "skills")
	must(t, os.MkdirAll(skills, 0o700))
	writeFile(t, filepath.Join(home, ".dccert", "mcp.json"), `{"mcpServers":{"dccert-marker":{}}}`)
	writeFile(t, filepath.Join(home, ".bash_history"), strings.Repeat("echo dccert-block-marker\n", 200))
	writeFile(t, filepath.Join(home, "big.json"), strings.Repeat("x", 4096))
	must(t, syscall.Mkfifo(filepath.Join(home, ".dccert", "pipe.json"), 0o600))
	must(t, syscall.Mkfifo(filepath.Join(skills, "fifo-skill"), 0o600))
	must(t, os.Symlink("/etc", filepath.Join(skills, "linked")))
	writeFile(t, filepath.Join(skills, "new\nline"), "x")
	for i := range 600 {
		must(t, os.Mkdir(filepath.Join(skills, fmt.Sprintf("s%03d", i)), 0o700))
	}
	project := filepath.Join(top, "work")
	writeFile(t, filepath.Join(project, "package.json"), `{"name":"dccert"}`)
	writeFile(t, filepath.Join(project, "node_modules", "dep", "package.json"), `{"name":"dep"}`)
	writeFile(t, filepath.Join(project, ".git", "package.json"), `{}`)
	scope := newCollectScope()
	scope.roots = []string{top}
	pairs := []string{
		"C", filepath.Join(home, ".dccert", "mcp.json"), "C", filepath.Join(home, ".dccert", "pipe.json"), "C", filepath.Join(home, "big.json"),
		"H", filepath.Join(home, ".bash_history"), "D3", skills, "W", project, "M", "package.json", "K", ".git",
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		switch pairs[i] {
		case "C", "H":
			scope.exact[pairs[i+1]], scope.content[pairs[i+1]] = true, true
		case "D3":
			scope.dirs[pairs[i+1]] = 3
		case "W":
			scope.walks = append(scope.walks, pairs[i+1])
		case "M":
			scope.manifests[pairs[i+1]] = true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	argv := collectArgv("discover", 1024, pairs)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.Output()
	if ctx.Err() != nil {
		t.Fatal("the collector hung")
	}
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	c, err := parseCollection(out, false, scope, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Ended {
		t.Fatalf("problems = %v, want a complete answer", c.Problems)
	}
	if string(c.Contents[filepath.Join(home, ".dccert", "mcp.json")]) != `{"mcpServers":{"dccert-marker":{}}}` {
		t.Fatalf("mcp content = %q", c.Contents)
	}
	if hist := c.Contents[filepath.Join(home, ".bash_history")]; len(hist) != 1024 || !strings.HasSuffix(string(hist), "dccert-block-marker\n") {
		t.Fatalf("history = %d bytes, want its last 1024", len(hist))
	}
	if _, ok := c.Contents[filepath.Join(home, "big.json")]; ok {
		t.Fatal("a file over the bound was read")
	}
	if _, ok := c.Contents[filepath.Join(home, ".dccert", "pipe.json")]; ok {
		t.Fatal("a FIFO was read")
	}
	children := 0
	for _, e := range c.Entries {
		if strings.Contains(e.Path, "line") {
			t.Fatalf("entry %q with a newline kept", e.Path)
		}
		if strings.Contains(e.Path, ".git") {
			t.Fatalf("a manifest inside .git was listed: %s", e.Path)
		}
		if filepath.Dir(e.Path) == skills {
			children++
		}
	}
	if children > collectDirEntries {
		t.Fatalf("listed %d children, want at most %d", children, collectDirEntries)
	}
	if _, ok := c.Contents[filepath.Join(project, "node_modules", "dep", "package.json")]; !ok {
		t.Fatalf("contents = %v, want the nested manifest", c.Contents)
	}
	// The collector's own processes are this account's.
	if len(c.Processes) == 0 || c.Boot.IsZero() {
		t.Fatalf("processes = %d boot = %v", len(c.Processes), c.Boot)
	}
	root := filepath.Join(t.TempDir(), "root")
	if _, err := writeCollectedTree(root, c); err != nil {
		t.Fatal(err)
	}
}
