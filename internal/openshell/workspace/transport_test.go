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
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

var _ Transport = (*CLI)(nil)

func TestCLIArgv(t *testing.T) {
	c := &CLI{Binary: "/usr/bin/openshell", Gateway: "openshell", Workspace: "default"}
	argv, err := c.UploadArgv("f1-x", "/stage/myapp", "/sandbox/work")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got !=
		"/usr/bin/openshell sandbox upload -g openshell --workspace default --color never --no-git-ignore -- f1-x /stage/myapp /sandbox/work" {
		t.Fatalf("upload argv = %s", got)
	}
	argv, err = c.DownloadArgv("f1-x", "/sandbox/.dc/result.bundle", "/tmp/pull")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got !=
		"/usr/bin/openshell sandbox download -g openshell --workspace default --color never -- f1-x /sandbox/.dc/result.bundle /tmp/pull" {
		t.Fatalf("download argv = %s", got)
	}
	argv, err = c.ExecArgv("f1-x", ExecRequest{
		Argv: []string{"sh", "-c", "echo hi"}, Workdir: "/sandbox", Timeout: 1500 * time.Millisecond,
		Env: map[string]string{"B": "2", "A": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got !=
		"/usr/bin/openshell sandbox exec -g openshell --workspace default --color never --name f1-x --workdir /sandbox --timeout 12 --no-tty --no-login-shell --env A=1 --env B=2 -- timeout -k 5 1.5 sh -c echo hi" {
		t.Fatalf("exec argv = %s", got)
	}
	// The workspace defaults to openshell's; the binary to the one on PATH.
	bare := &CLI{Gateway: "gw"}
	if argv, err := bare.UploadArgv("s", "/a", "/b"); err != nil || strings.Join(argv, " ") !=
		"openshell sandbox upload -g gw --workspace default --color never --no-git-ignore -- s /a /b" {
		t.Fatalf("default binary argv = %q, %v", argv, err)
	}
	for _, env := range []map[string]string{{"BAD-KEY": "x"}, {"K": "line\nbreak"}, {"K": "cr\rhere"}} {
		if _, err := c.ExecArgv("s", ExecRequest{Argv: []string{"true"}, Env: env}); err == nil {
			t.Fatalf("env %v accepted", env)
		}
	}
	if _, err := c.ExecArgv("s", ExecRequest{}); err == nil {
		t.Fatal("empty command accepted")
	}
	if _, err := c.ExecArgv("s", ExecRequest{Argv: []string{"true"}, Workdir: "relative"}); err == nil {
		t.Fatal("relative workdir accepted")
	}
	// Names that are not DNS labels never reach the binary as positionals.
	for _, bad := range []string{"-g", "Upper", "a b", ""} {
		if _, err := c.UploadArgv(bad, "/a", "/b"); err == nil {
			t.Fatalf("sandbox %q accepted", bad)
		}
	}
}

// TestCLIRequiresAnExplicitGateway: without -g the openshell binary uses
// whichever gateway is active or named by the environment, so an unset or
// malformed gateway is refused before anything runs.
func TestCLIRequiresAnExplicitGateway(t *testing.T) {
	for _, c := range []*CLI{{}, {Gateway: "-bad"}, {Gateway: "gw", Workspace: "../ws"}} {
		ran := 0
		c.run = fakeRun(func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
			ran++
			return nil, nil, 0, nil
		})
		if err := c.Upload(bg, "s", "/a", "/b"); err == nil {
			t.Errorf("%+v: upload accepted", c)
		}
		if err := c.Download(bg, "s", "/a", "/b"); err == nil {
			t.Errorf("%+v: download accepted", c)
		}
		if _, err := c.Exec(bg, "s", ExecRequest{Argv: []string{"true"}}); err == nil {
			t.Errorf("%+v: exec accepted", c)
		}
		if ran != 0 {
			t.Errorf("%+v: ran the binary %d times", c, ran)
		}
	}
}

// TestRunProcessScrubsGatewayEnvironment: the variables that would point
// the openshell binary at another gateway, or turn off TLS verification,
// never reach it.
func TestRunProcessScrubsGatewayEnvironment(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	for _, k := range []string{"OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_INSECURE", "OPENSHELL_WORKSPACE"} {
		t.Setenv(k, "marker")
	}
	t.Setenv("DC_WORKSPACE_TEST_KEEP", "kept")
	ctx, cancel := context.WithTimeout(bg, 10*time.Second)
	defer cancel()
	script := `for k in OPENSHELL_GATEWAY OPENSHELL_GATEWAY_ENDPOINT OPENSHELL_GATEWAY_INSECURE OPENSHELL_WORKSPACE; do ` +
		`eval "v=\${$k-unset}"; printf '%s=%s\n' "$k" "$v"; done; printf 'keep=%s\n' "$DC_WORKSPACE_TEST_KEEP"`
	var stdout strings.Builder
	stderr, code, err := runProcess(ctx, []string{"sh", "-c", script}, &stdout)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v stderr=%s", code, err, stderr)
	}
	want := "OPENSHELL_GATEWAY=unset\nOPENSHELL_GATEWAY_ENDPOINT=unset\nOPENSHELL_GATEWAY_INSECURE=unset\nOPENSHELL_WORKSPACE=unset\nkeep=kept\n"
	if stdout.String() != want {
		t.Fatalf("child environment:\n%s", stdout.String())
	}
}

// scriptedCLI answers exec attempts in order; the last answer repeats.
type scriptedCLI struct {
	answers []func(ctx context.Context) ([]byte, []byte, int, error)
	argv    [][]string
}

func (s *scriptedCLI) cli() *CLI {
	return &CLI{Gateway: "gw", run: fakeRun(func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		s.argv = append(s.argv, argv)
		return s.answers[min(len(s.argv), len(s.answers))-1](ctx)
	})}
}

// fakeRun turns a scripted answer into CLI's process seam.
func fakeRun(f func(ctx context.Context, argv []string) ([]byte, []byte, int, error)) func(context.Context, []string, io.Writer) ([]byte, int, error) {
	return func(ctx context.Context, argv []string, stdout io.Writer) ([]byte, int, error) {
		out, stderr, code, err := f(ctx, argv)
		if len(out) > 0 {
			if _, werr := stdout.Write(out); werr != nil {
				return stderr, -1, werr
			}
		}
		return stderr, code, err
	}
}

func answer(stdout, stderr string, code int) func(context.Context) ([]byte, []byte, int, error) {
	return func(context.Context) ([]byte, []byte, int, error) { return []byte(stdout), []byte(stderr), code, nil }
}

func TestCLIExecWrapsTheCommandInTimeout(t *testing.T) {
	s := &scriptedCLI{answers: []func(context.Context) ([]byte, []byte, int, error){answer("ok\n", "", 0)}}
	if _, err := s.cli().Exec(bg, "s", ExecRequest{Argv: []string{"git", "status"}, Timeout: 90 * time.Second}); err != nil {
		t.Fatal(err)
	}
	argv := s.argv[0]
	sep := -1
	for i, a := range argv {
		if a == "--" {
			sep = i
			break
		}
	}
	cmd, limit, ok := openshell.ParseSandboxTimeoutArgv(argv[sep+1:])
	if sep < 0 || !ok || limit != 90*time.Second || strings.Join(cmd, " ") != "git status" {
		t.Fatalf("argv = %q", argv)
	}
	// The binary's own --timeout (which leaves the command running) comes
	// only after the sandbox has had time to stop it.
	if got := strings.Join(argv[:sep], " "); !strings.Contains(got, "--timeout 100") {
		t.Fatalf("CLI --timeout: %s", got)
	}
}

func TestCLIExecRetriesOnlyIdempotentSilence(t *testing.T) {
	type answers = []func(context.Context) ([]byte, []byte, int, error)
	cases := []struct {
		name       string
		idempotent bool
		attempts   int
		answers    answers
		wantCalls  int
		wantCode   int
		wantErr    error
	}{
		// The post-create flake: a silent failure, then an answer.
		{"idempotent silent failure is retried", true, 0, answers{answer("", "", 255), answer("ok\n", "", 0)}, 2, 0, nil},
		// A command that is not idempotent may have run: never again.
		{"other silent failure is returned", false, 0, answers{answer("", "", 255), answer("ok\n", "", 0)}, 1, 255, nil},
		{"an exit with output is an answer", true, 0, answers{answer("", "no such file", 2)}, 1, 2, nil},
		// "test -e" failing quietly, every time, is an answer too.
		{"persistent silence returns the status", true, 3, answers{answer("", "", 1)}, 3, 1, nil},
		// OpenShell reports 124 when its --timeout or the sandbox's
		// timeout(1) fired; the command may still be finishing.
		{"a silent 124 after the timeout is not retried", true, 0, answers{answer("", "", 124), answer("ok\n", "", 0)}, 1, 0, openshell.ErrExecTimeout},
		{"a silent 124 is not retried either way", false, 0, answers{answer("", "", 124), answer("ok\n", "", 0)}, 1, 0, openshell.ErrExecTimeout},
		{"a killed command is a timeout", true, 0, answers{answer("", "", 137)}, 1, 0, openshell.ErrExecTimeout},
		{"a missing timeout(1) is reported", true, 0, answers{answer("", "sh: 1: timeout: not found", 127)}, 1, 0, openshell.ErrNoSandboxTimeout},
		{"a binary that cannot start is not retried", true, 0, answers{func(context.Context) ([]byte, []byte, int, error) {
			return nil, nil, -1, errors.New("fork failed")
		}}, 1, 0, errors.New("")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptedCLI{answers: tc.answers}
			c := s.cli()
			c.Attempts = tc.attempts
			res, err := c.Exec(bg, "s", ExecRequest{Argv: []string{"sh", "-c", "x"}, Timeout: time.Nanosecond, Idempotent: tc.idempotent})
			if len(s.argv) != tc.wantCalls {
				t.Fatalf("ran %d times, want %d", len(s.argv), tc.wantCalls)
			}
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("err = %v", err)
			case tc.wantErr != nil && err == nil:
				t.Fatalf("res = %+v, want an error", res)
			case tc.wantErr != nil && tc.wantErr.Error() != "" && !errors.Is(err, tc.wantErr):
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			case tc.wantErr == nil && res.ExitCode != tc.wantCode:
				t.Fatalf("exit = %d, want %d", res.ExitCode, tc.wantCode)
			}
		})
	}
}

// TestCLIExecDeadlineIsNotRetriedUnlessIdempotent: an attempt that never
// answered is only rerun for an idempotent command, and only when it
// printed nothing.
func TestCLIExecDeadlineIsNotRetriedUnlessIdempotent(t *testing.T) {
	hang := func(ctx context.Context) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}
	talkThenHang := func(ctx context.Context) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return []byte("partial"), nil, -1, ctx.Err()
	}
	for _, tc := range []struct {
		name       string
		idempotent bool
		first      func(context.Context) ([]byte, []byte, int, error)
		wantCalls  int
	}{
		{"not idempotent", false, hang, 1},
		{"idempotent and silent", true, hang, 2},
		{"idempotent but it printed", true, talkThenHang, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptedCLI{answers: []func(context.Context) ([]byte, []byte, int, error){tc.first, answer("ok\n", "", 0)}}
			c := s.cli()
			c.attemptLimit = 20 * time.Millisecond
			res, err := c.Exec(bg, "s", ExecRequest{Argv: []string{"true"}, Idempotent: tc.idempotent})
			if len(s.argv) != tc.wantCalls {
				t.Fatalf("ran %d times, want %d", len(s.argv), tc.wantCalls)
			}
			if tc.wantCalls == 1 && !errors.Is(err, openshell.ErrExecTimeout) {
				t.Fatalf("res=%+v err=%v, want a timeout", res, err)
			}
			if tc.wantCalls == 2 && (err != nil || string(res.Stdout) != "ok\n") {
				t.Fatalf("res=%+v err=%v", res, err)
			}
		})
	}
}

// failAfter accepts limit bytes, then fails every write.
type failAfter struct {
	limit int
	got   strings.Builder
}

var errWriterFull = errors.New("writer full")

func (f *failAfter) Write(p []byte) (int, error) {
	if f.got.Len()+len(p) > f.limit {
		return 0, errWriterFull
	}
	return f.got.WriteString(string(p))
}

func TestCLIExecStreamsStdout(t *testing.T) {
	calls := 0
	c := &CLI{Gateway: "gw", run: func(ctx context.Context, argv []string, stdout io.Writer) ([]byte, int, error) {
		calls++
		for i := 0; i < 4; i++ {
			if _, err := stdout.Write([]byte("marker")); err != nil {
				// The writer's error cancelled the attempt.
				if ctx.Err() == nil {
					t.Error("the attempt was not stopped")
				}
				return nil, -1, err
			}
		}
		return nil, 0, nil
	}}
	w := &failAfter{limit: 1 << 10}
	res, err := c.Exec(bg, "s", ExecRequest{Argv: []string{"cat", "f"}, Stdout: w})
	if err != nil || len(res.Stdout) != 0 || w.got.String() != strings.Repeat("marker", 4) {
		t.Fatalf("res=%+v err=%v streamed=%q", res, err, w.got.String())
	}
	calls = 0
	_, err = c.Exec(bg, "s", ExecRequest{Argv: []string{"cat", "f"}, Stdout: &failAfter{limit: 10}, Idempotent: true})
	if !errors.Is(err, errWriterFull) || calls != 1 {
		t.Fatalf("err=%v calls=%d, want the writer's error from one attempt", err, calls)
	}
}

func TestCLIExecTimesOutAndRespectsCancel(t *testing.T) {
	c := &CLI{Gateway: "gw", ExecTimeout: time.Millisecond, Attempts: 1, run: fakeRun(func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	})}
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
	c := &CLI{Gateway: "gw", run: fakeRun(func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		return nil, []byte("line1\nError: × ssh tar extract exited with status 2\n"), 1, nil
	})}
	err := c.Upload(bg, "s", "/a", "/work")
	if err == nil || !strings.Contains(err.Error(), "tar extract") {
		t.Fatalf("err = %v", err)
	}
	c.run = fakeRun(func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		return nil, nil, -1, errors.New("exec: not found")
	})
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
	var stdout strings.Builder
	_, code, err := runProcess(ctx, []string{"sh", "-c", "cat; echo done; exit 3"}, &stdout)
	if err != nil || code != 3 || stdout.String() != "done\n" {
		t.Fatalf("stdout=%q code=%d err=%v", stdout.String(), code, err)
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
