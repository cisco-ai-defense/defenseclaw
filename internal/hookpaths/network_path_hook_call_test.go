// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// hookCallShares is two shares that do not answer and one that answers in
// 100 ms (500 ms for newSlowHookCallShares), below the 750 ms answer wait. The answering share holds an
// ordinary sourced script and one that writes the local keys file.
type hookCallShares struct {
	home, dead, dead2, live, keys string
	deadAsked                     chan struct{}
}

func newHookCallShares(t *testing.T) hookCallShares {
	t.Helper()
	return newSlowHookCallShares(t, 100*time.Millisecond)
}

func newSlowHookCallShares(t *testing.T, liveAnswersIn time.Duration) hookCallShares {
	t.Helper()
	home := t.TempDir()
	s := hookCallShares{
		home: home, dead: filepath.Join(home, "dead-share"), dead2: filepath.Join(home, "dead-share-2"),
		live: filepath.Join(home, "live-share"),
		keys: filepath.Join(home, ".ssh", "authorized_keys"), deadAsked: make(chan struct{}),
	}
	for _, dir := range []string{s.dead, s.dead2, s.live, filepath.Dir(s.keys)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		s.keys:                             "k\n",
		filepath.Join(s.live, "safe.sh"):   "echo ordinary > report.txt\n",
		filepath.Join(s.live, "writer.sh"): "echo k >> ~/.ssh/authorized_keys\n",
	} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var asked sync.Once
	fakeNetworkShare(t, s.dead, 750*time.Millisecond, 5*time.Second, func(root string) {
		if strings.HasPrefix(root, s.dead) || strings.HasPrefix(root, s.dead2) {
			asked.Do(func() { close(s.deadAsked) })
			<-release
			return
		}
		time.Sleep(liveAnswersIn)
	})
	networkShareRootOf = func(path string) string {
		for _, root := range []string{s.dead, s.dead2, s.live} {
			if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
				return root
			}
		}
		return ""
	}
	return s
}

// The answering share is read: its ordinary script, and the keys write of
// the other.
func (s hookCallShares) checkLiveRead(t *testing.T) {
	t.Helper()
	if content, read := readIndirectSource("safe.sh", s.live); !read || content != "echo ordinary > report.txt\n" {
		t.Errorf("the answering share was not read: read %v, content %q", read, content)
	}
	if operands := LiteralWriteOperands("source writer.sh", s.live, s.home); !slices.Contains(operands, s.keys) {
		t.Errorf("the keys write of a script on the answering share was not seen: operands %q, want %q", operands, s.keys)
	}
}

// rel-1-0-6:GAP-0482 (review 2): the gateway answers many hook calls in one
// process. A call that spent its wait on a share that does not answer
// leaves the next call its own wait, so the next call reads a share that
// answers, and sees what a script there writes.
func TestSeparateHookCallsEachHaveTheirOwnShareWait(t *testing.T) {
	s := newHookCallShares(t)
	first := HookCall()
	start := time.Now()
	if !networkPathUnanswered(filepath.Join(s.dead, "notes.txt")) {
		t.Fatal("the share that does not answer answered")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the first call waited %v", took)
	}
	first()
	second := HookCall()
	defer second()
	s.checkLiveRead(t)
}

// Reads outside a hook call each wait for their own share, as before.
func TestReadsOutsideAHookCallEachWaitForTheirShare(t *testing.T) {
	s := newHookCallShares(t)
	if !networkPathUnanswered(filepath.Join(s.dead, "notes.txt")) {
		t.Fatal("the share that does not answer answered")
	}
	s.checkLiveRead(t)
}

// Two calls at once, as two hook requests the gateway answers together:
// the wait one has spent on a share that does not answer, while it still
// runs, is not the other's.
func TestConcurrentHookCallsEachHaveTheirOwnShareWait(t *testing.T) {
	s := newHookCallShares(t)
	spent, done := make(chan bool, 1), make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer HookCall()()
		spent <- networkPathUnanswered(filepath.Join(s.dead, "notes.txt"))
		<-done
	}()
	if !<-spent {
		t.Fatal("the share that does not answer answered")
	}
	func() {
		defer HookCall()()
		s.checkLiveRead(t)
	}()
	close(done)
	<-finished
}

// A call that resolves its targets inside a hook call (the gateway request
// that runs ResolveConnector) is that call: it does not begin a second wait.
func TestHookCallInsideAHookCallSharesItsWait(t *testing.T) {
	const shares, spent = 10, 6
	release := make(chan struct{})
	defer close(release)
	fakeNetworkShare(t, "/dead0.example/share", 750*time.Millisecond, 5*time.Second, func(string) { <-release })
	networkShareRootOf = func(path string) string {
		for i := range shares {
			root := fmt.Sprintf("/dead%d.example/share", i)
			if strings.HasPrefix(filepath.ToSlash(path), root+"/") {
				return root
			}
		}
		return ""
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var commands []string
	for i := spent; i < shares; i++ {
		commands = append(commands, fmt.Sprintf("echo ordinary > /dead%d.example/share/notes.txt", i))
	}
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": home,
		"tool_input": map[string]string{"command": strings.Join(commands, "; ")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer HookCall()()
	for i := range spent {
		if !networkPathUnanswered(fmt.Sprintf("/dead%d.example/share/notes.txt", i)) {
			t.Fatal("the share that does not answer answered")
		}
	}
	start := time.Now()
	if _, ok := Decode(Resolve(payload)); !ok {
		t.Fatal("Resolve gave no target map")
	}
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Fatalf("the target resolution inside a hook call that spent its wait waited %v more", took)
	}
}

// rel-1-0-6:GAP-0482 (review 3): within one hook call, a share that does not
// answer costs the call its own wait and no other share its chance. An
// answering share asked after it is read, and a script there that writes
// the local keys file is seen.
func TestOneHookCallDeadShareDoesNotStarveAnAnsweringShare(t *testing.T) {
	s := newHookCallShares(t)
	defer HookCall()()
	if !networkPathUnanswered(filepath.Join(s.dead, "notes.txt")) {
		t.Fatal("the share that does not answer answered")
	}
	s.checkLiveRead(t)
}

// rel-1-0-6:GAP-0482 (review 4): the full waits of a call spent on shares
// that do not answer do not leave a share that answers unread. The third
// share, asked after two that did not answer, is read, and a script there
// that writes the local keys file is seen.
func TestOneHookCallTwoDeadSharesDoNotStarveAnAnsweringShare(t *testing.T) {
	s := newHookCallShares(t)
	defer HookCall()()
	for _, dead := range []string{s.dead, s.dead2} {
		if !networkPathUnanswered(filepath.Join(dead, "notes.txt")) {
			t.Fatal("the share that does not answer answered")
		}
	}
	s.checkLiveRead(t)
}

// rel-1-0-6:GAP-0482 (review 6): the third share answers in 500 ms, inside
// the 750 ms answer wait, after two that did not answer have spent two
// waits. It is read, and the script there that writes the local keys file
// through its protected path is seen, as it is on a build with no share
// bound. The call stays inside its budget.
func TestOneHookCallTwoDeadSharesDoNotStarveAShareAnsweringInHalfTheWait(t *testing.T) {
	s := newSlowHookCallShares(t, 500*time.Millisecond)
	defer HookCall()()
	start := time.Now()
	for _, dead := range []string{s.dead, s.dead2} {
		if !networkPathUnanswered(filepath.Join(dead, "notes.txt")) {
			t.Fatal("the share that does not answer answered")
		}
	}
	s.checkLiveRead(t)
	if took, bound := time.Since(start), networkShareCallWaits*networkShareAnswerWait+150*time.Millisecond; took > bound {
		t.Errorf("the call waited %v, want at most %v", took, bound)
	}
}

// The benign twin: the same call without the shares that do not answer
// reads the answering share, and its ordinary script writes nothing
// protected.
func TestOneHookCallAnsweringShareAloneIsReadWithoutProtectedWrite(t *testing.T) {
	s := newHookCallShares(t)
	defer HookCall()()
	if operands := LiteralWriteOperands("source safe.sh", s.live, s.home); slices.Contains(operands, s.keys) {
		t.Errorf("an ordinary script on the answering share is read as a keys write: %q", operands)
	}
}

// The bound of a call holds: shares that do not answer cost it no more than
// networkShareCallWaits answer waits and the slack of a loaded test host, and
// a share asked after that reads as unknown at once. The wait count moved
// from two to three for review 6 (a share answering in half its wait, asked
// after two that did not); the slack is the one of review 1.
func TestOneHookCallWaitIsBoundedAcrossDeadShares(t *testing.T) {
	const shares = 6
	release := make(chan struct{})
	defer close(release)
	fakeNetworkShare(t, "/dead0.example/share", 200*time.Millisecond, 5*time.Second, func(string) { <-release })
	networkShareRootOf = func(path string) string {
		for i := range shares {
			root := fmt.Sprintf("/dead%d.example/share", i)
			if strings.HasPrefix(filepath.ToSlash(path), root+"/") {
				return root
			}
		}
		return ""
	}
	defer HookCall()()
	start := time.Now()
	for i := range shares {
		if !networkPathUnanswered(fmt.Sprintf("/dead%d.example/share/notes.txt", i)) {
			t.Fatal("the share that does not answer answered")
		}
	}
	bound := networkShareCallWaits*200*time.Millisecond + 150*time.Millisecond
	if took := time.Since(start); took > bound {
		t.Fatalf("%d shares that do not answer held the call %v, want at most %v", shares, took, bound)
	}
}
