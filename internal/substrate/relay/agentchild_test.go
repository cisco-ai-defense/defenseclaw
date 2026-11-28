// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The headless-task tests need a child that stands in for the agent. They
// used sh, so they failed on Windows ("exec: sh not found", GAP-0963)
// although the relay only runs the argv it is given. The test binary is now
// the stand-in: TestMain hands "relay-test-agent <mode> [args]" to
// testAgent, so the same relay path runs on Linux, macOS and Windows.

const testAgentArg = "relay-test-agent"

// agentArgv is the argv of a stand-in agent that runs mode. {prompt} is
// last, as in a real connector template.
func agentArgv(mode string, args ...string) []string {
	argv := []string{os.Args[0], testAgentArg, mode}
	argv = append(argv, args...)
	return append(argv, "{prompt}")
}

// isTestAgent reports whether the binary was started as a stand-in agent.
func isTestAgent(args []string) bool { return len(args) > 1 && args[0] == testAgentArg }

// testAgent runs one stand-in behaviour and returns the exit code. args is
// os.Args[1:]: the marker, the mode, the mode's arguments, the prompt.
func testAgent(args []string) int {
	mode, rest := args[1], args[2:]
	prompt := ""
	if len(rest) > 0 {
		prompt, rest = rest[len(rest)-1], rest[:len(rest)-1]
	}
	switch mode {
	case "echo-mode":
		// Output on both streams, the prompt and the actor mode, exit 3.
		fmt.Printf("out:%s mode:%s\n", prompt, os.Getenv("DEFENSECLAW_ACTOR_MODE"))
		fmt.Fprintln(os.Stderr, "err")
		return 3
	case "fault":
		// The hook met the outage: record one unanswered call as the kit
		// hook does, then exit with $CODE.
		if f := os.Getenv("DEFENSECLAW_TASK_FAULTS"); f != "" {
			if w, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600); err == nil {
				fmt.Fprintln(w, "2026-11-15T06:32:10Z PostToolUse")
				_ = w.Close()
			}
		}
		fmt.Println("step-1-done")
		code, _ := strconv.Atoi(os.Getenv("CODE"))
		return code
	case "faults-env":
		if os.Getenv("DEFENSECLAW_TASK_FAULTS") != "" {
			fmt.Println("faults=set")
		} else {
			fmt.Println("faults=")
		}
		return 0
	case "silent":
		// Print once, then wait without output: the stall tests.
		fmt.Println("started")
		time.Sleep(10 * time.Minute)
		return 0
	case "ignore-term":
		// Ignores TERM and keeps running, so only KILL ends it. Windows has
		// no TERM: the relay kills at once there and the test still holds.
		signal.Ignore(syscall.SIGTERM)
		for {
			time.Sleep(time.Second)
		}
	case "retry-loop":
		for {
			fmt.Println(`{"type":"system","subtype":"api_retry","attempt":1}`)
			time.Sleep(100 * time.Millisecond)
		}
	case "talk":
		// rest[0] lines, one every 200 ms, then exit 0.
		n, _ := strconv.Atoi(rest[0])
		for i := 0; i < n; i++ {
			fmt.Println(i)
			time.Sleep(200 * time.Millisecond)
		}
		return 0
	case "sleep":
		// Silent for the duration in rest[0], then exit 0.
		d, _ := time.ParseDuration(rest[0])
		time.Sleep(d)
		return 0
	case "child-holds-output":
		// A background child holds stdout open, its PID goes to rest[0],
		// and the agent exits 4.
		c := exec.Command(os.Args[0], testAgentArg, "sleep", "30s", "x")
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 99
		}
		if err := os.WriteFile(rest[0], []byte(strings.TrimSpace(strconv.Itoa(c.Process.Pid))), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 99
		}
		fmt.Println("bye")
		return 4
	}
	fmt.Fprintln(os.Stderr, "unknown test agent mode", mode)
	return 98
}
