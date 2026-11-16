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

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// rel-1-0-2:GAP-0419 (#1202): after the account's OpenShell gateway was
// stopped (a SIGTERM), a start the daemon asks while the unit is still
// stopping is a no-op, and the unit stays inactive. The wait starts it
// again, so the sandbox command goes on; a gateway that never listens is
// refused in a sentence, without the gateway's internal address or the
// unit's state, which go to the log.
func TestAccountOpenShellStartsAGatewayThatStoppedBeforeItListened(t *testing.T) {
	fastGatewayWaits(t)
	every := openShellGatewayRestartEvery
	openShellGatewayRestartEvery = 0
	t.Cleanup(func() { openShellGatewayRestartEvery = every })
	for _, tc := range []struct {
		name   string
		listen bool
	}{{"the second start listens", true}, {"it never listens", false}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newOpenShellRig(t, "linux")
			var mu sync.Mutex
			starts := 0
			var logged []string
			r.o.logf = func(format string, args ...any) {
				mu.Lock()
				defer mu.Unlock()
				logged = append(logged, fmt.Sprintf(format, args...))
			}
			run := r.o.run
			r.o.run = func(ctx context.Context, name string, args, env []string) (string, error) {
				line := filepath.Base(name) + " " + strings.Join(args, " ")
				mu.Lock()
				defer mu.Unlock()
				switch {
				case strings.HasPrefix(line, "systemctl --user start "):
					starts++
				case strings.HasPrefix(line, "systemctl --user show "):
					return "LoadState=loaded\nActiveState=inactive\nSubState=dead\nExecMainStatus=0\n", nil
				}
				return run(ctx, name, args, env)
			}
			r.holder = func(int) int {
				mu.Lock()
				defer mu.Unlock()
				if tc.listen && starts >= 2 {
					return 5001
				}
				return 0
			}
			began := time.Now()
			_, err := r.o.ensureRunning(context.Background(), 17690, "")
			mu.Lock()
			defer mu.Unlock()
			if tc.listen {
				if err != nil || starts != 2 {
					t.Fatalf("restart: err=%v starts=%d", err, starts)
				}
				return
			}
			var apiErr *sandboxapi.Error
			if !errors.As(err, &apiErr) || starts != 1+openShellGatewayRestarts || time.Since(began) > 5*time.Second {
				t.Fatalf("never listens: err=%v starts=%d", err, starts)
			}
			text := apiErr.Message + " " + apiErr.Detail
			for _, raw := range []string{"127.0.0.1", "17690", "inactive", "the unit is", "exit status", "systemctl"} {
				if strings.Contains(text, raw) {
					t.Fatalf("refusal shows %q: %q", raw, text)
				}
			}
			if !strings.Contains(text, "did not start listening within") || !strings.Contains(strings.Join(logged, "\n"), "127.0.0.1:17690") {
				t.Fatalf("refusal %q, log %q", text, logged)
			}
		})
	}
}
