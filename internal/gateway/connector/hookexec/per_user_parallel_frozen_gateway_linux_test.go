// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	parallelHookAddrEnv = "DEFENSECLAW_TEST_PARALLEL_HOOK_ADDR"
	parallelHookDirEnv  = "DEFENSECLAW_TEST_PARALLEL_HOOK_DIR"
)

// TestParallelHookProcessChild is one of the separate hook processes the test
// below starts. It runs the real native hook path for an ordinary command in
// the default (open) outage mode against the frozen gateway.
func TestParallelHookProcessChild(t *testing.T) {
	addr, dir := os.Getenv(parallelHookAddrEnv), os.Getenv(parallelHookDirEnv)
	if addr == "" || dir == "" {
		t.Skip("started only by TestParallelHookProcessesFollowTheOutageModeOfAFrozenGateway")
	}
	project := lateOrdinaryProject(t)
	client, err := NewPerUserGatewayHTTPClient(10*time.Second, addr)
	if err != nil {
		t.Fatal(err)
	}
	result := run(t, "claudecode", nil, func(opts *Options) {
		opts.APIAddr = addr
		opts.HTTPClient = client
		opts.Event = "PreToolUse"
		opts.Home = dir
		opts.FailMode = "open"
		opts.OutageFailModeNow = func() string { return "open" }
		opts.Stdin = strings.NewReader(lateOrdinaryPayload(t, project, "echo hi"))
	})
	if output := result.stdout + result.stderr; nativeOutageBlocked(result) || strings.Contains(output, "could not prove") {
		t.Fatalf("ordinary call blocked: code=%d output=%.400q", result.code, output)
	}
}

// Many hook processes of one account start together while its recorded
// gateway is frozen (an agent runs its tool calls in parallel). Each one is a
// separate process, and each reads the other hook processes of the account
// while it proves who holds the listener. A hook process in the middle of
// starting or ending is not the gateway and not a copy of its sockets, so none
// of them may turn an ordinary call into a refusal.
func TestParallelHookProcessesFollowTheOutageModeOfAFrozenGateway(t *testing.T) {
	addr, dataDir, pid := startRealGateway(t)
	freezeProcess(t, pid)
	const width, waves = 25, 4
	failures := 0
	for wave := 0; wave < waves; wave++ {
		results := make([]string, width)
		var group sync.WaitGroup
		for i := range results {
			group.Add(1)
			go func() {
				defer group.Done()
				cmd := exec.Command(os.Args[0], "-test.run=^TestParallelHookProcessChild$", "-test.timeout=60s")
				cmd.Env = append(os.Environ(), parallelHookAddrEnv+"="+addr, parallelHookDirEnv+"="+dataDir, "GOMAXPROCS=2")
				if out, err := cmd.CombinedOutput(); err != nil {
					results[i] = fmt.Sprintf("%v: %.600s", err, out)
				}
			}()
		}
		group.Wait()
		for _, failed := range results {
			if failed == "" {
				continue
			}
			if failures++; failures <= 3 {
				t.Log(failed)
			}
		}
	}
	if failures != 0 {
		t.Fatalf("%d of %d parallel hook processes did not follow the outage mode of the frozen own gateway", failures, width*waves)
	}
}
