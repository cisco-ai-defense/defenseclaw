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

package workspace

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var _ Transport = (*CLI)(nil)

func TestCLIArgv(t *testing.T) {
	c := &CLI{Binary: "/usr/bin/openshell", Gateway: "openshell", Workspace: "default"}
	if got := strings.Join(c.UploadArgv("f1-x", "/stage/myapp", "/sandbox/work"), " "); got !=
		"/usr/bin/openshell sandbox upload -g openshell --workspace default --no-git-ignore f1-x /stage/myapp /sandbox/work" {
		t.Fatalf("upload argv = %s", got)
	}
	if got := strings.Join(c.DownloadArgv("f1-x", "/sandbox/.dc/result.bundle", "/tmp/pull"), " "); got !=
		"/usr/bin/openshell sandbox download -g openshell --workspace default f1-x /sandbox/.dc/result.bundle /tmp/pull" {
		t.Fatalf("download argv = %s", got)
	}
	argv, err := c.ExecArgv("f1-x", ExecRequest{
		Argv: []string{"sh", "-c", "echo hi"}, Workdir: "/sandbox", Timeout: 1500 * time.Millisecond,
		Env: map[string]string{"B": "2", "A": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got !=
		"/usr/bin/openshell sandbox exec -g openshell --workspace default -n f1-x --no-tty --no-login-shell --workdir /sandbox --timeout 2 --env A=1 --env B=2 -- sh -c echo hi" {
		t.Fatalf("exec argv = %s", got)
	}
	bare := &CLI{}
	if got := strings.Join(bare.UploadArgv("s", "/a", "/b"), " "); got != "openshell sandbox upload --no-git-ignore s /a /b" {
		t.Fatalf("default binary argv = %s", got)
	}
	for _, env := range []map[string]string{{"BAD-KEY": "x"}, {"K": "line\nbreak"}} {
		if _, err := c.ExecArgv("s", ExecRequest{Argv: []string{"true"}, Env: env}); err == nil {
			t.Fatalf("env %v accepted", env)
		}
	}
	if _, err := c.ExecArgv("s", ExecRequest{}); err == nil {
		t.Fatal("empty command accepted")
	}
}

func TestCLIExecRetriesSilentFailures(t *testing.T) {
	calls := 0
	c := &CLI{run: func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		calls++
		if calls == 1 {
			return nil, nil, 255, nil // the post-create flake: no output at all
		}
		return []byte("ok\n"), nil, 0, nil
	}}
	res, err := c.Exec(bg, "s", ExecRequest{Argv: []string{"true"}})
	if err != nil || calls != 2 || string(res.Stdout) != "ok\n" {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, calls)
	}

	// A real non-zero exit with output is an answer, not a retry.
	calls = 0
	c.run = func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		calls++
		return nil, []byte("no such file"), 2, nil
	}
	res, err = c.Exec(bg, "s", ExecRequest{Argv: []string{"false"}})
	if err != nil || calls != 1 || res.ExitCode != 2 {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, calls)
	}

	// Persistent silence is retried, then returned as the exit code it is
	// ("test -e" failing quietly).
	calls = 0
	c.Attempts = 3
	c.run = func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		calls++
		return nil, nil, 1, nil
	}
	res, err = c.Exec(bg, "s", ExecRequest{Argv: []string{"test", "-e", "/x"}})
	if err != nil || calls != 3 || res.ExitCode != 1 {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, calls)
	}

	// Failures to run at all are errors.
	c.run = func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		return nil, nil, -1, errors.New("fork failed")
	}
	if _, err := c.Exec(bg, "s", ExecRequest{Argv: []string{"x"}}); err == nil {
		t.Fatal("start failure ignored")
	}
}

func TestCLIExecTimesOutAndRespectsCancel(t *testing.T) {
	c := &CLI{ExecTimeout: time.Millisecond, Attempts: 1, run: func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}}
	start := time.Now()
	ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	defer cancel()
	if _, err := c.Exec(ctx, "s", ExecRequest{Argv: []string{"sleep", "100"}}); err == nil {
		t.Fatal("expected an error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("exec did not stop at the context deadline")
	}
}

func TestCLITransferErrors(t *testing.T) {
	c := &CLI{run: func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		return nil, []byte("line1\nError: × ssh tar extract exited with status 2\n"), 1, nil
	}}
	err := c.Upload(bg, "s", "/a", "/work")
	if err == nil || !strings.Contains(err.Error(), "tar extract") {
		t.Fatalf("err = %v", err)
	}
	c.run = func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		return nil, nil, -1, errors.New("exec: not found")
	}
	if err := c.Download(bg, "s", "/a", "/tmp"); err == nil {
		t.Fatal("start failure ignored")
	}
}

func TestRunProcessReadsStdinFromDevNull(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	ctx, cancel := context.WithTimeout(bg, 10*time.Second)
	defer cancel()
	stdout, _, code, err := runProcess(ctx, []string{"sh", "-c", "cat; echo done; exit 3"})
	if err != nil || code != 3 || string(stdout) != "done\n" {
		t.Fatalf("stdout=%q code=%d err=%v", stdout, code, err)
	}
}

func TestShellQuoteAndParseKV(t *testing.T) {
	if got := shellQuote("it's /a b"); got != `'it'\''s /a b'` {
		t.Fatalf("shellQuote = %s", got)
	}
	kv := parseKV([]byte("head=abc\nremote=remote.a.url x\nremote=remote.b.url y\r\njunk\n"))
	if kv["head"] != "abc" || kv["remote"] != "remote.a.url x\nremote.b.url y" {
		t.Fatalf("parseKV = %v", kv)
	}
	if r := parseRemotes(kv["remote"]); r["a"] != "x" || r["b"] != "y" {
		t.Fatalf("parseRemotes = %v", r)
	}
	for raw, want := range map[string]string{
		"https://u:tok@github.com/a/b.git": "https://github.com/a/b.git",
		"https://u@github.com/a/b.git":     "https://github.com/a/b.git",
		"ssh://git@github.com/a/b.git":     "ssh://git@github.com/a/b.git",
		"ssh://git:pw@github.com/a/b.git":  "ssh://github.com/a/b.git",
		"git@github.com:a/b.git":           "git@github.com:a/b.git",
		"/srv/repo.git":                    "",
		"../up.git":                        "",
		"file:///srv/repo.git":             "",
		"ext::sh -c evil":                  "",
	} {
		got, ok := sanitizeRemoteURL(raw)
		if (want == "") == ok || got != want {
			t.Errorf("sanitizeRemoteURL(%q) = %q,%v want %q", raw, got, ok, want)
		}
	}
}
