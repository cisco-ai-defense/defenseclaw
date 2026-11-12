// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package relay

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fileEnv struct {
	t   *testing.T
	s   *Server
	srv *httptest.Server
	tok string
}

func newFileEnv(t *testing.T) *fileEnv {
	t.Helper()
	s, _, _, ec := testServer(t, []string{"sh"})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &fileEnv{t: t, s: s, srv: srv, tok: ec.token(t, claims(time.Now(), nil), TokenType)}
}

func (e *fileEnv) do(method, path string, body io.Reader, token string) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func (e *fileEnv) status(method, path string, body io.Reader) (int, string) {
	e.t.Helper()
	resp := e.do(method, path, body, e.tok)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

type execResult struct {
	status int
	stdout []byte
	stderr []byte
	code   int
	text   string
}

func (e *fileEnv) exec(req any) execResult {
	e.t.Helper()
	body, _ := json.Marshal(req)
	resp := e.do("POST", "/dcrelay/1/exec", bytes.NewReader(body), e.tok)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read exec reply: %v", err)
	}
	res := execResult{status: resp.StatusCode, code: -1}
	if resp.StatusCode != http.StatusOK {
		res.text = string(raw)
		return res
	}
	exits := 0
	for len(raw) > 0 {
		if len(raw) < 5 {
			e.t.Fatalf("truncated frame header: %d bytes", len(raw))
		}
		n := int(binary.BigEndian.Uint32(raw[1:5]))
		if len(raw) < 5+n {
			e.t.Fatalf("truncated frame payload")
		}
		p := raw[5 : 5+n]
		switch raw[0] {
		case ExecStdout:
			res.stdout = append(res.stdout, p...)
		case ExecStderr:
			res.stderr = append(res.stderr, p...)
		case ExecExit:
			exits++
			res.code, err = strconv.Atoi(string(p))
			if err != nil {
				e.t.Fatalf("exit frame %q", p)
			}
		default:
			e.t.Fatalf("frame type %d", raw[0])
		}
		raw = raw[5+n:]
	}
	if exits != 1 {
		e.t.Fatalf("%d exit frames", exits)
	}
	return res
}

func TestFileRoutesNeedASessionToken(t *testing.T) {
	e := newFileEnv(t)
	for _, tc := range []struct{ method, path string }{
		{"POST", "/dcrelay/1/exec"}, {"PUT", "/dcrelay/1/files?dir=/tmp/x"}, {"GET", "/dcrelay/1/files?path=/tmp"},
	} {
		for _, token := range []string{"", "not.a.token"} {
			resp := e.do(tc.method, tc.path, strings.NewReader(`{"argv":["true"]}`), token)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s token=%q: status %d", tc.method, tc.path, token, resp.StatusCode)
			}
		}
	}
}

func TestExecExitCodesAndStreams(t *testing.T) {
	e := newFileEnv(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	for _, tc := range []struct {
		name       string
		req        ExecRequest
		out, errOu string
		code       int
	}{
		{"exit zero", ExecRequest{Argv: []string{"true"}}, "", "", 0},
		{"streams and code", ExecRequest{Argv: []string{"sh", "-c", "printf hello; printf oops >&2; exit 3"}}, "hello", "oops", 3},
		{"stdin is empty", ExecRequest{Argv: []string{"cat"}}, "", "", 0},
		{"env", ExecRequest{Argv: []string{"sh", "-c", `printf "%s" "$DC_TEST_1"`}, Env: map[string]string{"DC_TEST_1": "v 1"}}, "v 1", "", 0},
		{"workdir", ExecRequest{Argv: []string{"pwd", "-P"}, Workdir: dir}, dir + "\n", "", 0},
		{"killed by a signal", ExecRequest{Argv: []string{"sh", "-c", "kill -9 $$"}}, "", "", 137},
		{"no shell expansion", ExecRequest{Argv: []string{"printf", "%s", "$HOME;id"}}, "$HOME;id", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := e.exec(tc.req)
			if r.status != 200 || string(r.stdout) != tc.out || string(r.stderr) != tc.errOu || r.code != tc.code {
				t.Fatalf("%+v", r)
			}
		})
	}
	t.Run("command not found", func(t *testing.T) {
		r := e.exec(ExecRequest{Argv: []string{"/nonexistent/dc-cmd"}})
		if r.status != 200 || r.code != ExitNotRunnable || len(r.stderr) == 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("large output arrives whole", func(t *testing.T) {
		r := e.exec(ExecRequest{Argv: []string{"head", "-c", "200000", "/dev/zero"}})
		if r.code != 0 || len(r.stdout) != 200000 {
			t.Fatalf("code %d, %d bytes", r.code, len(r.stdout))
		}
	})
}

func TestExecRefusesBadRequests(t *testing.T) {
	e := newFileEnv(t)
	for name, req := range map[string]any{
		"no argv":          ExecRequest{},
		"empty command":    ExecRequest{Argv: []string{""}},
		"NUL in argv":      ExecRequest{Argv: []string{"true", "a\x00b"}},
		"lowercase env":    ExecRequest{Argv: []string{"true"}, Env: map[string]string{"path": "x"}},
		"dash in env name": ExecRequest{Argv: []string{"true"}, Env: map[string]string{"A-B": "x"}},
		"empty env name":   ExecRequest{Argv: []string{"true"}, Env: map[string]string{"": "x"}},
		"NUL in env":       ExecRequest{Argv: []string{"true"}, Env: map[string]string{"A": "x\x00"}},
		"negative timeout": ExecRequest{Argv: []string{"true"}, TimeoutSeconds: -1},
		"huge timeout":     ExecRequest{Argv: []string{"true"}, TimeoutSeconds: 1 << 30},
		"negative cap":     ExecRequest{Argv: []string{"true"}, MaxOutputBytes: -1},
		"not an object":    []int{1},
	} {
		if r := e.exec(req); r.status != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, r.status)
		}
	}
	if code, _ := e.status("POST", "/dcrelay/1/exec", strings.NewReader("{")); code != http.StatusBadRequest {
		t.Errorf("broken JSON: %d", code)
	}
}

// processGone reports whether pid no longer runs (a zombie nobody reaped
// counts as gone).
func processGone(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return true
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	return i > 0 && strings.HasPrefix(strings.TrimSpace(s[i+1:]), "Z")
}

func TestExecTimeoutStopsTheProcessGroup(t *testing.T) {
	e := newFileEnv(t)
	start := time.Now()
	r := e.exec(ExecRequest{Argv: []string{"sh", "-c", "sleep 60 & echo $!; wait"}, TimeoutSeconds: 1})
	if r.status != 200 || r.code != ExitTimedOut || string(r.stderr) != "timed out" {
		t.Fatalf("%+v", r)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %s", d)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(r.stdout)))
	if err != nil {
		t.Fatalf("child pid %q", r.stdout)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !processGone(pid) {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the sleep started by the command still runs (pid %d)", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestExecOutputCap(t *testing.T) {
	e := newFileEnv(t)
	r := e.exec(ExecRequest{Argv: []string{"yes"}, MaxOutputBytes: 1000, TimeoutSeconds: 30})
	if r.status != 200 || r.code != ExitOutputLimit || len(r.stdout) != 1000 || !strings.Contains(string(r.stderr), "output limit") {
		t.Fatalf("code %d, %d bytes, stderr %q", r.code, len(r.stdout), r.stderr)
	}
	// Both streams share the budget.
	r = e.exec(ExecRequest{Argv: []string{"sh", "-c", "head -c 600 /dev/zero; head -c 600 /dev/zero >&2"}, MaxOutputBytes: 1000})
	if r.code != ExitOutputLimit || len(r.stdout) != 600 || len(r.stderr) < 400 {
		t.Fatalf("code %d, %d + %d bytes", r.code, len(r.stdout), len(r.stderr))
	}
}

type ent struct {
	name string
	typ  byte
	mode int64
	body string
	link string
}

func mkTar(t *testing.T, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, en := range ents {
		typ := en.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: en.name, Typeflag: typ, Mode: en.mode, Linkname: en.link, ModTime: time.Unix(1700000000, 0)}
		if typ == tar.TypeReg {
			h.Size = int64(len(en.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(en.body))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func mustWrite(t *testing.T, name, body string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(name, mode)
}

// tree lists a directory as "path mode content|-> target" lines.
func tree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		info, _ := d.Info()
		line := rel + " " + strconv.FormatUint(uint64(info.Mode().Perm()), 8)
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			line += " -> " + l
		case info.Mode().IsRegular():
			b, _ := os.ReadFile(p)
			line += " " + string(b)
		default:
			line += " dir"
		}
		out = append(out, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFilesRoundTripKeepsModesAndLinks(t *testing.T) {
	e := newFileEnv(t)
	src := t.TempDir()
	proj := filepath.Join(src, "proj")
	mustWrite(t, filepath.Join(proj, "a.txt"), "alpha", 0o644)
	mustWrite(t, filepath.Join(proj, "bin", "run.sh"), "#!/bin/sh\n", 0o755)
	mustWrite(t, filepath.Join(proj, "key.pem"), "k", 0o600)
	if err := os.Mkdir(filepath.Join(proj, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(proj, "private", "n"), "n", 0o640)
	os.Chmod(filepath.Join(proj, "private"), 0o700)
	if err := os.Symlink("a.txt", filepath.Join(proj, "ln")); err != nil {
		t.Fatal(err)
	}
	// A link that leaves the tree is kept as a link.
	if err := os.Symlink("/etc/dc-nonexistent", filepath.Join(proj, "abs")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteTar(&buf, proj); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "x", "y")
	if code, msg := e.status("PUT", "/dcrelay/1/files?dir="+dst, &buf); code != http.StatusNoContent {
		t.Fatalf("put: %d %s", code, msg)
	}
	want := tree(t, proj)
	if got := tree(t, filepath.Join(dst, "proj")); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("uploaded tree differs\n got %q\nwant %q", got, want)
	}
	// Download it again, as a directory and as one file.
	resp := e.do("GET", "/dcrelay/1/files?path="+filepath.Join(dst, "proj"), nil, e.tok)
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-tar" {
		t.Fatalf("get: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	back := t.TempDir()
	if _, err := ExtractTar(resp.Body, back, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := tree(t, filepath.Join(back, "proj")); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("downloaded tree differs\n got %q\nwant %q", got, want)
	}
	resp2 := e.do("GET", "/dcrelay/1/files?path="+filepath.Join(dst, "proj", "bin", "run.sh"), nil, e.tok)
	defer resp2.Body.Close()
	one := t.TempDir()
	if _, err := ExtractTar(resp2.Body, one, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(one, "run.sh")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("single file: %v %v", fi, err)
	}
}

func TestFilesRelativePathsUseTheRelayWorkdir(t *testing.T) {
	e := newFileEnv(t)
	wd := t.TempDir()
	e.s.opts.Config.Relay.Workdir = wd
	body := mkTar(t, ent{name: "p/f", mode: 0o644, body: "z"})
	if code, msg := e.status("PUT", "/dcrelay/1/files?dir=up/here", bytes.NewReader(body)); code != 204 {
		t.Fatalf("%d %s", code, msg)
	}
	if b, err := os.ReadFile(filepath.Join(wd, "up", "here", "p", "f")); err != nil || string(b) != "z" {
		t.Fatalf("%q %v", b, err)
	}
	if code, _ := e.status("GET", "/dcrelay/1/files?path=up/here/p", nil); code != 200 {
		t.Fatalf("get %d", code)
	}
	r := e.exec(ExecRequest{Argv: []string{"cat", "up/here/p/f"}})
	if string(r.stdout) != "z" {
		t.Fatalf("exec did not start in the workdir: %+v", r)
	}
	code, msg := e.status("GET", "/dcrelay/1/status", nil)
	var st map[string]any
	if code != 200 || json.Unmarshal([]byte(msg), &st) != nil || st["workdir"] != wd {
		t.Fatalf("status %d %s", code, msg)
	}
}

func TestPutRefusesUnsafeArchives(t *testing.T) {
	for _, tc := range []struct {
		name string
		ents func(outside string) []ent
	}{
		{"absolute path", func(o string) []ent { return []ent{{name: filepath.Join(o, "abs"), mode: 0o644, body: "x"}} }},
		{"parent escape", func(string) []ent { return []ent{{name: "../escape", mode: 0o644, body: "x"}} }},
		{"nested escape", func(string) []ent { return []ent{{name: "a/../../escape", mode: 0o644, body: "x"}} }},
		{"escape of a directory entry", func(string) []ent { return []ent{{name: "../d/", typ: tar.TypeDir, mode: 0o755}} }},
		{"write through a link out", func(o string) []ent {
			return []ent{{name: "ln", typ: tar.TypeSymlink, link: o}, {name: "ln/escape", mode: 0o644, body: "x"}}
		}},
		{"write through a relative link out", func(string) []ent {
			return []ent{{name: "ln", typ: tar.TypeSymlink, link: "../.."}, {name: "ln/escape", mode: 0o644, body: "x"}}
		}},
		{"directory through a link out", func(o string) []ent {
			return []ent{{name: "ln", typ: tar.TypeSymlink, link: o}, {name: "ln/sub/", typ: tar.TypeDir, mode: 0o755}}
		}},
		{"character device", func(string) []ent { return []ent{{name: "dev", typ: tar.TypeChar, mode: 0o644}} }},
		{"fifo", func(string) []ent { return []ent{{name: "pipe", typ: tar.TypeFifo, mode: 0o644}} }},
		{"hard link", func(string) []ent {
			return []ent{{name: "a", mode: 0o644, body: "x"}, {name: "b", typ: tar.TypeLink, link: "a"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newFileEnv(t)
			base := t.TempDir()
			outside := filepath.Join(base, "outside")
			dst := filepath.Join(base, "dst")
			if err := os.Mkdir(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			code, msg := e.status("PUT", "/dcrelay/1/files?dir="+dst, bytes.NewReader(mkTar(t, tc.ents(outside)...)))
			if code != http.StatusBadRequest {
				t.Fatalf("status %d %s", code, msg)
			}
			// Nothing appeared outside the destination.
			left, _ := os.ReadDir(outside)
			baseEntries, _ := os.ReadDir(base)
			if len(left) != 0 || len(baseEntries) != 2 {
				t.Fatalf("outside: %v, base: %v", left, baseEntries)
			}
		})
	}
	t.Run("not a tar", func(t *testing.T) {
		e := newFileEnv(t)
		code, _ := e.status("PUT", "/dcrelay/1/files?dir="+t.TempDir(), strings.NewReader(strings.Repeat("x", 2000)))
		if code != http.StatusBadRequest {
			t.Fatalf("status %d", code)
		}
	})
	t.Run("no dir", func(t *testing.T) {
		e := newFileEnv(t)
		if code, _ := e.status("PUT", "/dcrelay/1/files", bytes.NewReader(mkTar(t))); code != http.StatusBadRequest {
			t.Fatalf("status %d", code)
		}
	})
}

func TestPutKeepsEscapingLinksButNeverFollowsExistingOnes(t *testing.T) {
	e := newFileEnv(t)
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	mustWrite(t, victim, "keep", 0o644)
	dst := filepath.Join(base, "dst")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	// The destination already holds a link out; the archive's file replaces
	// the link and does not write through it.
	if err := os.Symlink(victim, filepath.Join(dst, "f")); err != nil {
		t.Fatal(err)
	}
	body := mkTar(t,
		ent{name: "f", mode: 0o644, body: "new"},
		ent{name: "kept", typ: tar.TypeSymlink, link: "/somewhere/else"},
		ent{name: "./", typ: tar.TypeDir, mode: 0o755})
	if code, msg := e.status("PUT", "/dcrelay/1/files?dir="+dst, bytes.NewReader(body)); code != 204 {
		t.Fatalf("%d %s", code, msg)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("a file outside the destination was written: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "f")); string(b) != "new" {
		t.Fatalf("f = %q", b)
	}
	if l, err := os.Readlink(filepath.Join(dst, "kept")); err != nil || l != "/somewhere/else" {
		t.Fatalf("link %q %v", l, err)
	}
}

func TestPutAppliesDirectoryModesLast(t *testing.T) {
	e := newFileEnv(t)
	dst := t.TempDir()
	body := mkTar(t,
		ent{name: "ro/", typ: tar.TypeDir, mode: 0o555},
		ent{name: "ro/f", mode: 0o444, body: "x"})
	if code, msg := e.status("PUT", "/dcrelay/1/files?dir="+dst, bytes.NewReader(body)); code != 204 {
		t.Fatalf("%d %s", code, msg)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(dst, "ro"), 0o755) })
	if fi, err := os.Stat(filepath.Join(dst, "ro")); err != nil || fi.Mode().Perm() != 0o555 {
		t.Fatalf("%v %v", fi, err)
	}
}

func TestPutSizeCap(t *testing.T) {
	t.Setenv(FilesMaxBytesEnv, "1000")
	e := newFileEnv(t)
	for _, tc := range []struct {
		name string
		ents []ent
		want int
	}{
		{"one file over", []ent{{name: "big", mode: 0o644, body: strings.Repeat("x", 2000)}}, http.StatusRequestEntityTooLarge},
		{"many files over together", []ent{{name: "a", mode: 0o644, body: strings.Repeat("x", 600)}, {name: "b", mode: 0o644, body: strings.Repeat("x", 600)}}, http.StatusRequestEntityTooLarge},
		{"under the cap", []ent{{name: "ok", mode: 0o644, body: strings.Repeat("x", 900)}}, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, msg := e.status("PUT", "/dcrelay/1/files?dir="+t.TempDir(), bytes.NewReader(mkTar(t, tc.ents...))); code != tc.want {
				t.Fatalf("status %d %s", code, msg)
			}
		})
	}
	t.Run("many small entries over the body bound", func(t *testing.T) {
		var ents []ent
		for i := 0; i < 2500; i++ {
			ents = append(ents, ent{name: "d" + strconv.Itoa(i) + "/", typ: tar.TypeDir, mode: 0o755})
		}
		if code, _ := e.status("PUT", "/dcrelay/1/files?dir="+t.TempDir(), bytes.NewReader(mkTar(t, ents...))); code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d", code)
		}
	})
}

func TestGetMissingAndEmptyPath(t *testing.T) {
	e := newFileEnv(t)
	if code, _ := e.status("GET", "/dcrelay/1/files?path="+filepath.Join(t.TempDir(), "nope"), nil); code != http.StatusNotFound {
		t.Fatalf("missing: %d", code)
	}
	if code, _ := e.status("GET", "/dcrelay/1/files", nil); code != http.StatusBadRequest {
		t.Fatalf("empty: %d", code)
	}
}

func TestWriteTarSkipsSpecialFilesAndExtractTarEnforcesTheCap(t *testing.T) {
	src := filepath.Join(t.TempDir(), "p")
	mustWrite(t, filepath.Join(src, "f"), strings.Repeat("y", 500), 0o644)
	if err := syscall.Mkfifo(filepath.Join(src, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteTar(&buf, src); err != nil {
		t.Fatal(err)
	}
	var names []string
	tr := tar.NewReader(bytes.NewReader(buf.Bytes()))
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	if strings.Join(names, ",") != "p/,p/f" {
		t.Fatalf("names %v", names)
	}
	_, err := ExtractTar(bytes.NewReader(buf.Bytes()), t.TempDir(), ExtractOptions{MaxBytes: 100})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
	if err := WriteTar(io.Discard, "/"); err == nil {
		t.Fatal("archived the file system root")
	}
}
