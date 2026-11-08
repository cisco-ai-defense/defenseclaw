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

	// frozenGatewayJobEnv is set to 1 only by the dedicated CI job "Go Test
	// (frozen gateway, alone)" in .github/workflows/ci.yml.
	frozenGatewayJobEnv = "DEFENSECLAW_FROZEN_GATEWAY_JOB"
)

// requireFrozenGatewayJob skips a frozen-gateway test in every run except the
// dedicated CI job, which runs them with -p 1 and no other test process of the
// account. The hook proves who holds a listener by reading every other process
// of its account, and it refuses (by design) a same-account holder it cannot
// see into. Another test binary running as the same account (the deliberate
// mixed-credential and private-thread helpers of the hookexec tests, or the
// parallel packages of a shared runner) is such a holder, so these tests are
// only meaningful when nothing else of the account runs.
func requireFrozenGatewayJob(t *testing.T) {
	t.Helper()
	if os.Getenv(frozenGatewayJobEnv) != "1" {
		t.Skip("runs only in the CI job \"Go Test (frozen gateway, alone)\" (" + frozenGatewayJobEnv + "=1): it needs a run in which no other test process of this account exists")
	}
}

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
	requireFrozenGatewayJob(t)
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
