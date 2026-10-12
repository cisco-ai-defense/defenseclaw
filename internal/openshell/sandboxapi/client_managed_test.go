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

package sandboxapi

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestManagedSocketPath(t *testing.T) {
	restore := managedRuntimeDir
	t.Cleanup(func() { managedRuntimeDir = restore })
	managedRuntimeDir = func() string { return "/run/user/1001" }
	if got := ManagedSocketPath("linux", 1001, "/home/a"); got != "/run/user/1001/defenseclaw/sandbox.sock" {
		t.Fatalf("linux: %q", got)
	}
	for _, bad := range []string{"", "relative", "/run/user/1001/../x"} {
		managedRuntimeDir = func() string { return bad }
		if got := ManagedSocketPath("linux", 1002, ""); got != "/run/user/1002/defenseclaw/sandbox.sock" {
			t.Fatalf("XDG_RUNTIME_DIR %q: %q", bad, got)
		}
	}
	if got := ManagedSocketPath("darwin", 501, "/Users/ent-alice"); got != "/Users/ent-alice/Library/Application Support/DefenseClaw Sandbox/sandbox.sock" {
		t.Fatalf("darwin: %q", got)
	}
	for _, c := range []struct {
		goos string
		uid  int
		home string
	}{{"darwin", 501, ""}, {"darwin", 501, "rel"}, {"windows", 1, `C:\Users\a`}, {"linux", 0, "/root"}} {
		if got := ManagedSocketPath(c.goos, c.uid, c.home); got != "" {
			t.Fatalf("%+v: %q", c, got)
		}
	}
}

func TestClientForHostNeedsTheManagedDescriptor(t *testing.T) {
	restore := managedHostDescriptor
	t.Cleanup(func() { managedHostDescriptor = restore })
	managedHostDescriptor = func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor }
	if _, err := ClientForHost("linux"); !errors.Is(err, ErrNotManagedHost) {
		t.Fatalf("no descriptor: %v", err)
	}
	if _, err := ClientForHost("windows"); !errors.Is(err, ErrNotManagedHost) {
		t.Fatalf("windows: %v", err)
	}
	managedHostDescriptor = func(string) (*managed.RuntimeDescriptor, error) { return nil, errors.New("owned by a user") }
	if _, err := ClientForHost("linux"); err == nil || errors.Is(err, ErrNotManagedHost) {
		t.Fatalf("untrusted descriptor fell back: %v", err)
	}
	managedHostDescriptor = func(string) (*managed.RuntimeDescriptor, error) { return &managed.RuntimeDescriptor{}, nil }
	c, err := ClientForHost("linux")
	if os.Getuid() == 0 {
		if err == nil {
			t.Fatal("root got a sandbox daemon client")
		}
		return
	}
	if err != nil || c.BaseURL != managedDaemonBaseURL || c.Token != "" {
		t.Fatalf("managed client: %+v %v", c, err)
	}
}

// The unix client sends no token and refuses a socket the caller does not
// own alone.
func TestUnixClientTalksToTheOwnDaemonOnly(t *testing.T) {
	dir, err := os.MkdirTemp("", "sbd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sandbox.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var auth string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, `{"enabled":true}`)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := NewUnixClient(path)
	st, err := c.Status(context.Background())
	if err != nil || !st.Enabled || auth != "" {
		t.Fatalf("status %+v err %v auth %q", st, err, auth)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("a socket in a world-writable directory was used")
	}
}
