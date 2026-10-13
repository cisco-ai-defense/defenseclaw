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

//go:build linux

package sandboxfeed

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeFeed serves one header and then frames on a unix socket in a private
// directory, as the test's own uid.
func fakeFeed(t *testing.T, header Header, frames ...any) (string, <-chan Request) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "feed")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "feed.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	requests := make(chan Request, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var request Request
				if err := ReadLine(NewLineScanner(conn), &request); err != nil {
					return
				}
				requests <- request
				_ = WriteLine(conn, header)
				for _, frame := range frames {
					_ = WriteLine(conn, frame)
				}
			}()
		}
	}()
	return path, requests
}

func ownTrust() trustPolicy { return trustPolicy{uid: os.Getuid()} }

func TestDialReadsTheHeaderAndFrames(t *testing.T) {
	pid := 57
	path, requests := fakeFeed(t, Header{Protocol: ProtocolVersion, Build: "1.2.3", Tetragon: TetragonConnected},
		Frame{Kind: FrameExec, SandboxID: "sb-1", ExecID: "e1", PID: pid},
		map[string]any{"kind": "from-a-newer-feed", "x": 1},
		Frame{Kind: FrameExit, ExecID: "e1"})
	conn, err := dial(context.Background(), path, ownTrust())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if request := <-requests; request != (Request{Version: ProtocolVersion, Op: OpSandboxExecs}) {
		t.Fatalf("request = %+v", request)
	}
	if h := conn.Header(); h.Build != "1.2.3" || h.Tetragon != TetragonConnected {
		t.Fatalf("header = %+v", h)
	}
	first, err := conn.Next()
	if err != nil || first.Kind != FrameExec || first.PID != pid {
		t.Fatalf("first = %+v, %v", first, err)
	}
	// A frame kind this build does not know is skipped.
	second, err := conn.Next()
	if err != nil || second.Kind != FrameExit {
		t.Fatalf("second = %+v, %v", second, err)
	}
}

// A feed speaking a protocol this gateway does not read is refused, so the
// manager falls back to the sampler (kernel_feed_version_skew).
func TestDialRefusesAFeedOfAnotherProtocol(t *testing.T) {
	for name, header := range map[string]Header{
		"newer":           {Protocol: ProtocolVersion + 1, Build: "9.0.0"},
		"refused request": {Protocol: ProtocolVersion, Error: HeaderErrorVersionSkew},
		"none":            {},
	} {
		path, _ := fakeFeed(t, header)
		_, err := dial(context.Background(), path, ownTrust())
		var skew *SkewError
		if !errors.Is(err, ErrVersionSkew) || !errors.As(err, &skew) || ReasonFor(err) != ReasonVersionSkew {
			t.Fatalf("%s: err = %v, want a version skew", name, err)
		}
	}
	path, _ := fakeFeed(t, Header{Protocol: ProtocolVersion, Error: HeaderErrorUnknownOp})
	if _, err := dial(context.Background(), path, ownTrust()); err == nil || errors.Is(err, ErrVersionSkew) {
		t.Fatalf("an unknown-op refusal = %v", err)
	}
}

func TestDialChecksTheSocket(t *testing.T) {
	ctx := context.Background()
	if _, err := dial(ctx, filepath.Join(t.TempDir(), "absent", "feed.sock"), ownTrust()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("absent directory: %v", err)
	}
	if _, err := dial(ctx, filepath.Join(t.TempDir(), "feed.sock"), ownTrust()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("absent socket: %v", err)
	}
	path, _ := fakeFeed(t, Header{Protocol: ProtocolVersion})
	// Another owner than the trusted one: root, in production.
	if _, err := dial(ctx, path, trustPolicy{uid: os.Getuid() + 1}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("socket of another owner: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := dial(ctx, path, ownTrust()); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("world-writable directory: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := dial(ctx, path, ownTrust()); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("world-writable socket: %v", err)
	}
	plain := filepath.Join(t.TempDir(), "feed.sock")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dial(ctx, plain, ownTrust()); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a regular file: %v", err)
	}
}

// The server's credentials are checked on the connection itself.
func TestCheckServerWantsTheTrustedUID(t *testing.T) {
	path, _ := fakeFeed(t, Header{Protocol: ProtocolVersion})
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := checkServer(conn, ownTrust()); err != nil {
		t.Fatalf("own uid: %v", err)
	}
	if err := checkServer(conn, trustPolicy{uid: os.Getuid() + 1}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("another uid: %v", err)
	}
}
