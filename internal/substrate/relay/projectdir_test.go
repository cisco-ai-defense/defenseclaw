//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0163: the person asks the agent to start in the copy of the project
// (dir on attach and task), so what it writes where it starts is what pull
// reads. Only a folder inside the relay working directory is accepted.
func TestAgentStartsInTheProjectFolder(t *testing.T) {
	s, _, ec := testServer(t, []string{"sh"})
	wd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(wd, "proj")
	if err := os.Mkdir(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	s.opts.Config.Relay.Workdir = wd
	s.opts.Config.Relay.Headless = []string{"sh", "-c", "pwd", "{prompt}"}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	const task = "where am I"
	post := func(body string) (int, string) {
		req, _ := http.NewRequest("POST", srv.URL+Path(RouteTask), strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), func(c map[string]any) { c["dc.task_sha256"] = TaskDigest(task) }), TokenType))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			b.WriteString(sc.Text() + "\n")
		}
		return resp.StatusCode, b.String()
	}
	for _, bad := range []string{"/etc", "../", wd + "/../x", wd + "/nope", "/"} {
		if code, _ := post(`{"prompt":"` + task + `","dir":"` + bad + `"}`); code != http.StatusBadRequest {
			t.Errorf("task dir %q answered %d, want 400", bad, code)
		}
	}
	code, out := post(`{"prompt":"` + task + `","dir":"` + proj + `"}`)
	if code != http.StatusOK || !strings.Contains(out, `"data":"`+proj+`"`) {
		t.Fatalf("task in the project folder: %d %s", code, out)
	}
	code, out = post(`{"prompt":"` + task + `","dir":"proj"}`)
	if code != http.StatusOK || !strings.Contains(out, `"data":"`+proj+`"`) {
		t.Fatalf("relative project folder: %d %s", code, out)
	}

	// Attach: a refused folder is a 400 before anything starts; an
	// accepted one is where the interactive agent starts.
	open := func(dir string) int {
		req, _ := http.NewRequest("POST", srv.URL+Path(RoutePoll)+"?cols=80&rows=24&dir="+url.QueryEscape(dir), nil)
		req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := open("/tmp"); code != http.StatusBadRequest {
		t.Errorf("attach dir outside answered %d", code)
	}
	if code := open(proj); code != http.StatusOK {
		t.Fatalf("attach dir proj answered %d", code)
	}
	s.agent.mu.Lock()
	dir, cmdDir := s.agent.Dir, ""
	if s.agent.cmd != nil {
		cmdDir = s.agent.cmd.Dir
	}
	s.agent.mu.Unlock()
	if dir != proj || cmdDir != proj {
		t.Errorf("agent dir %q, started in %q; want %q", dir, cmdDir, proj)
	}
}

// GAP-0163 residual (R3b, P4): a folder inside the working directory that is
// a link to a folder outside it is not "inside"; a link that stays inside is.
func TestProjectDirSymlinkOutOfWorkdirIsRefused(t *testing.T) {
	s, _, _ := testServer(t, []string{"sh"})
	wd, _ := filepath.EvalSymlinks(t.TempDir())
	out, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.MkdirAll(filepath.Join(wd, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(wd, "outside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(wd, "real"), filepath.Join(wd, "inside")); err != nil {
		t.Fatal(err)
	}
	s.opts.Config.Relay.Workdir = wd
	if d, err := s.projectDir("outside"); err == nil {
		t.Fatalf("a link to %s, outside the workdir, was accepted as start folder %s", out, d)
	}
	if d, err := s.projectDir("inside"); err != nil || d != filepath.Join(wd, "inside") {
		t.Fatalf("a link that stays inside the workdir: %q %v", d, err)
	}
}
