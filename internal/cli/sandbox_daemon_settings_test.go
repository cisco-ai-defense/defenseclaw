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

package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// silentSettings is a managed gateway that takes the settings read and
// never answers: it waits for the caller's deadline.
type silentSettings struct {
	sandboxrelay.Client
	calls atomic.Int64
	left  atomic.Int64 // the first read's time to its deadline, -1 for none
}

func (s *silentSettings) Settings(ctx context.Context) (sandboxrelay.DaemonSettings, error) {
	if s.calls.Add(1) == 1 {
		s.left.Store(-1)
		if dl, ok := ctx.Deadline(); ok {
			s.left.Store(int64(time.Until(dl)))
		}
	}
	<-ctx.Done()
	return sandboxrelay.DaemonSettings{}, fmt.Errorf("%w: %v", sandboxrelay.ErrGatewayUnreachable, ctx.Err())
}

// GAP-0608: with the managed gateway stopped (SIGSTOP), the daemon's
// start-up settings read waited for the relay client's two minutes, and
// the daemon answered nothing until the watchdog replaced the gateway
// (25 to 51 s). The read now has its own deadline and is not repeated: the
// daemon answers that sandboxes cannot run now (fail closed).
func TestSandboxDaemonSettingsGivesUpOnASilentGateway(t *testing.T) {
	if sandboxDaemonSettingsCallTimeout > 5*time.Second {
		t.Fatalf("the start-up settings read is bounded by %s, want at most 5 s", sandboxDaemonSettingsCallTimeout)
	}
	const bound = 50 * time.Millisecond
	relay := &silentSettings{}
	_, err := sandboxDaemonSettings(context.Background(), relay, bound)
	if err == nil || !strings.Contains(err.Error(), "did not answer within "+bound.String()) {
		t.Fatalf("err = %v, want the gateway did not answer within %s", err, bound)
	}
	if n := relay.calls.Load(); n != 1 {
		t.Fatalf("read the settings %d times from a gateway that did not answer, want once", n)
	}
	if left := time.Duration(relay.left.Load()); left < 0 || left > bound {
		t.Fatalf("the settings read had deadline %s, want its own bound of at most %s", left, bound)
	}
}

// The same over a real hook socket whose gateway accepts the connection
// and never writes: the relay client gives up at the read's own deadline.
func TestSandboxDaemonSettingsGivesUpOnAHookSocketThatNeverAnswers(t *testing.T) {
	dir, err := os.MkdirTemp("", "dsw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hook.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	held := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			held <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for {
			select {
			case c := <-held:
				_ = c.Close()
			default:
				return
			}
		}
	})
	relay, err := sandboxrelay.NewClient(sandboxrelay.ClientOptions{SocketPath: path, TrustedOwners: []int{os.Getuid()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	const bound = 100 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		_, err := sandboxDaemonSettings(context.Background(), relay, bound)
		done <- err
	}()
	select {
	case err = <-done:
	case <-time.After(20 * time.Second): // a guard against a hang, not the bound
		t.Fatal("the settings read still waits on a gateway that never answers")
	}
	if err == nil || !strings.Contains(err.Error(), "did not answer within") {
		t.Fatalf("err = %v, want the gateway did not answer", err)
	}
	if n := accepted.Load(); n != 1 {
		t.Fatalf("dialed a gateway that did not answer %d times, want once", n)
	}
}
