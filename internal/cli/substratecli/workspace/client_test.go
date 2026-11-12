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

//go:build unix

package workspace

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

func TestClientExec(t *testing.T) {
	a := newActor(t)
	c := a.client()
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	for _, tc := range []struct {
		name         string
		req          osw.ExecRequest
		out, errText string
		code         int
	}{
		{"streams and exit code", osw.ExecRequest{Argv: []string{"sh", "-c", "printf hello; printf oops >&2; exit 3"}}, "hello", "oops", 3},
		{"env", osw.ExecRequest{Argv: []string{"sh", "-c", `printf "%s" "$DC_A"`}, Env: map[string]string{"DC_A": "x y"}}, "x y", "", 0},
		{"workdir", osw.ExecRequest{Argv: []string{"pwd", "-P"}, Workdir: dir}, dir + "\n", "", 0},
		{"default workdir is the relay's", osw.ExecRequest{Argv: []string{"pwd", "-P"}}, a.workdir + "\n", "", 0},
		{"stdin is empty", osw.ExecRequest{Argv: []string{"cat"}}, "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := c.Exec(context.Background(), "ignored", tc.req)
			if err != nil || string(res.Stdout) != tc.out || string(res.Stderr) != tc.errText || res.ExitCode != tc.code {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
}

func TestClientExecStreamsToTheWriterAndStopsOnItsError(t *testing.T) {
	c := newActor(t).client()
	var got bytes.Buffer
	res, err := c.Exec(context.Background(), "", osw.ExecRequest{Argv: []string{"head", "-c", "300000", "/dev/zero"}, Stdout: &got})
	if err != nil || got.Len() != 300000 || len(res.Stdout) != 0 {
		t.Fatalf("streamed %d bytes, result %+v, %v", got.Len(), res, err)
	}
	stop := errors.New("enough")
	w := &failingWriter{after: 1000, err: stop}
	start := time.Now()
	_, err = c.Exec(context.Background(), "", osw.ExecRequest{Argv: []string{"yes"}, Timeout: time.Minute, Stdout: w})
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the command was not stopped")
	}
}

type failingWriter struct {
	after int
	n     int
	err   error
}

func (f *failingWriter) Write(p []byte) (int, error) {
	f.n += len(p)
	if f.n > f.after {
		return 0, f.err
	}
	return len(p), nil
}

func TestClientExecErrors(t *testing.T) {
	a := newActor(t)
	t.Run("timeout wraps ErrExecTimeout", func(t *testing.T) {
		_, err := a.client().Exec(context.Background(), "", osw.ExecRequest{Argv: []string{"sleep", "30"}, Timeout: time.Second})
		if !errors.Is(err, openshell.ErrExecTimeout) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a command that exits 124 itself is only an exit code", func(t *testing.T) {
		res, err := a.client().Exec(context.Background(), "", osw.ExecRequest{Argv: []string{"sh", "-c", "exit 124"}})
		if err != nil || res.ExitCode != 124 {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("no command", func(t *testing.T) {
		if _, err := a.client().Exec(context.Background(), "", osw.ExecRequest{}); err == nil {
			t.Fatal("empty command accepted")
		}
	})
	t.Run("refused by the actor", func(t *testing.T) {
		_, err := a.client().Exec(context.Background(), "", osw.ExecRequest{Argv: []string{"true"}, Env: map[string]string{"bad": "x"}})
		var h *HTTPError
		if !errors.As(err, &h) || h.Status != http.StatusBadRequest || !strings.Contains(err.Error(), "A-Z") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong token", func(t *testing.T) {
		c := NewClient(a.srv.Client(), a.srv.URL, func(context.Context) (string, error) { return "secret-wrong-token", nil })
		_, err := c.Exec(context.Background(), "", osw.ExecRequest{Argv: []string{"true"}})
		var h *HTTPError
		if !errors.As(err, &h) || h.Status != http.StatusUnauthorized || strings.Contains(err.Error(), "secret-wrong-token") {
			t.Fatalf("err = %v", err)
		}
		if !strings.Contains(err.Error(), "sign in again") {
			t.Fatalf("no way on: %v", err)
		}
	})
	t.Run("token source fails", func(t *testing.T) {
		c := NewClient(a.srv.Client(), a.srv.URL, func(context.Context) (string, error) { return "", errors.New("not signed in") })
		if _, err := c.Exec(context.Background(), "", osw.ExecRequest{Argv: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "not signed in") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("actor unreachable", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		url := dead.URL
		dead.Close()
		c := NewClient(&http.Client{}, url, func(context.Context) (string, error) { return testToken, nil })
		if _, err := c.Exec(context.Background(), "", osw.ExecRequest{Argv: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "in the actor") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := a.client().Exec(ctx, "", osw.ExecRequest{Argv: []string{"sleep", "30"}, Timeout: time.Minute})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	})
}

// flaky fails the first n round trips before they reach the actor.
type flaky struct {
	next  http.RoundTripper
	fail  int32
	calls atomic.Int32
}

func (f *flaky) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.calls.Add(1) <= f.fail {
		return nil, errors.New("connection reset")
	}
	return f.next.RoundTrip(r)
}

func TestClientRetriesOnlyIdempotentCommands(t *testing.T) {
	a := newActor(t)
	for _, tc := range []struct {
		name       string
		idempotent bool
		wantErr    bool
		wantCalls  int32
	}{{"idempotent", true, false, 3}, {"not idempotent", false, true, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &flaky{next: a.srv.Client().Transport, fail: 2}
			c := NewClient(&http.Client{Transport: f}, a.srv.URL, func(context.Context) (string, error) { return testToken, nil })
			res, err := c.Exec(context.Background(), "", osw.ExecRequest{Argv: []string{"echo", "ok"}, Idempotent: tc.idempotent})
			if (err != nil) != tc.wantErr || f.calls.Load() != tc.wantCalls {
				t.Fatalf("err = %v, calls = %d", err, f.calls.Load())
			}
			if !tc.wantErr && string(res.Stdout) != "ok\n" {
				t.Fatalf("%+v", res)
			}
		})
	}
}

// listing is "path mode content|-> target" for every entry below root.
func listing(t *testing.T, root string) []string {
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
			line += " " + strconv.Itoa(len(b)) + " " + string(b[:min(len(b), 20)])
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

func TestClientUploadAndDownloadKeepModesAndLinks(t *testing.T) {
	a := newActor(t)
	c := a.client()
	src := t.TempDir()
	proj := filepath.Join(src, "proj")
	write(t, proj, "a.txt", "alpha", 0o644)
	write(t, proj, "bin/run.sh", "#!/bin/sh\n", 0o755)
	write(t, proj, "key", "k", 0o600)
	write(t, proj, "big.bin", strings.Repeat("0123456789abcdef", 200000), 0o644) // 3.2 MB
	if err := os.Symlink("a.txt", filepath.Join(proj, "ln")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/outside/dc-test", filepath.Join(proj, "abs")); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(a.workdir, "up", "dir")
	if err := c.Upload(context.Background(), "ignored", proj, remote); err != nil {
		t.Fatal(err)
	}
	want := listing(t, proj)
	if got := listing(t, filepath.Join(remote, "proj")); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("remote differs\n got %q\nwant %q", got, want)
	}
	local := t.TempDir()
	if err := c.Download(context.Background(), "ignored", filepath.Join(remote, "proj"), local); err != nil {
		t.Fatal(err)
	}
	if got := listing(t, filepath.Join(local, "proj")); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("download differs\n got %q\nwant %q", got, want)
	}
	// One file lands as localDir/<basename>.
	one := t.TempDir()
	if err := c.Download(context.Background(), "", filepath.Join(remote, "proj", "bin", "run.sh"), one); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(one, "run.sh")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("%v %v", fi, err)
	}
	// A single local file uploads as remoteDir/<basename>.
	if err := c.Upload(context.Background(), "", filepath.Join(proj, "a.txt"), filepath.Join(a.workdir, "single")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(a.workdir, "single", "a.txt")); string(got) != "alpha" {
		t.Fatalf("single file: %q", got)
	}
}

func TestClientTransferErrors(t *testing.T) {
	a := newActor(t)
	c := a.client()
	t.Run("missing local path", func(t *testing.T) {
		if err := c.Upload(context.Background(), "", filepath.Join(t.TempDir(), "nope"), "/x"); err == nil {
			t.Fatal("no error")
		}
	})
	t.Run("missing remote path", func(t *testing.T) {
		err := c.Download(context.Background(), "", filepath.Join(a.workdir, "nope"), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "does not exist in the actor") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("local directory missing", func(t *testing.T) {
		if err := c.Download(context.Background(), "", a.workdir, filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Fatal("no error")
		}
	})
	t.Run("upload over the actor's cap is refused", func(t *testing.T) {
		t.Setenv(relay.FilesMaxBytesEnv, "1000")
		src := filepath.Join(t.TempDir(), "p")
		write(t, src, "big", strings.Repeat("x", 5000), 0o644)
		err := c.Upload(context.Background(), "", src, filepath.Join(a.workdir, "capped"))
		var h *HTTPError
		if !errors.As(err, &h) || h.Status != http.StatusRequestEntityTooLarge {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("download over the client's cap", func(t *testing.T) {
		src := filepath.Join(a.workdir, "dl")
		write(t, src, "big", strings.Repeat("x", 5000), 0o644)
		small := a.client()
		small.MaxDownloadBytes = 100
		err := small.Download(context.Background(), "", src, t.TempDir())
		if err == nil || !errors.Is(err, relay.ErrTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong token on upload", func(t *testing.T) {
		bad := NewClient(a.srv.Client(), a.srv.URL, func(context.Context) (string, error) { return "nope", nil })
		src := filepath.Join(t.TempDir(), "p")
		write(t, src, "f", "x", 0o644)
		var h *HTTPError
		if err := bad.Upload(context.Background(), "", src, "/x"); !errors.As(err, &h) || h.Status != http.StatusUnauthorized {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestClientRoot(t *testing.T) {
	a := newActor(t)
	c := a.client()
	if c.RemoteRoot != "" {
		t.Fatalf("RemoteRoot before detection: %q", c.RemoteRoot)
	}
	root, err := c.Root(context.Background())
	if err != nil || root != a.workdir || c.RemoteRoot != a.workdir {
		t.Fatalf("%q %q %v", root, c.RemoteRoot, err)
	}
	// A relay that does not report a working directory gets the default.
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"version":"dcrelay/1"}`) }))
	defer old.Close()
	c2 := NewClient(old.Client(), old.URL+"/", func(context.Context) (string, error) { return testToken, nil })
	if root, err := c2.DetectRoot(context.Background()); err != nil || root != DefaultRemoteRoot {
		t.Fatalf("%q %v", root, err)
	}
}
