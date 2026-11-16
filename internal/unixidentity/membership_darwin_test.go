//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rel-1-0-6:GAP-0326: the in-process check gives the answer
// `dsmemberutil checkmembership` gives, for the account running the test and
// for root, on groups it is in, groups it is not in and a gid no group has.
func TestGAP0326InProcessMembershipMatchesDSMemberUtil(t *testing.T) {
	if err := validateTrustedTool(darwinDSMemberUtil); err != nil {
		t.Skip(err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	gids, err := current.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	gids = append(gids, current.Gid, "0", "12", "20", "61", "80", "4000001")
	for _, uid := range []string{current.Uid, "0"} {
		for _, gid := range gids {
			u, _ := strconv.ParseUint(uid, 10, 32)
			g, _ := strconv.ParseUint(gid, 10, 32)
			got, err := openDirectoryUIDMember(uint32(u), uint32(g))
			if err != nil {
				t.Fatalf("uid %s gid %s: %v", uid, gid, err)
			}
			out, err := exec.Command(darwinDSMemberUtil, "checkmembership", "-u", uid, "-g", gid).Output()
			if err != nil {
				t.Fatalf("dsmemberutil uid %s gid %s: %v", uid, gid, err)
			}
			var want bool
			switch strings.TrimSpace(string(out)) {
			case "user is a member of the group":
				want = true
			case "user is not a member of the group":
			default:
				t.Fatalf("dsmemberutil uid %s gid %s: %q", uid, gid, out)
			}
			if got != want {
				t.Errorf("uid %s gid %s: in process %t, dsmemberutil %t", uid, gid, got, want)
			}
		}
	}
}

// The refresh-span fixture of rel-1-0-6:GAP-0326. One refresh of the
// directory facts of an account in 95 groups (the lab Mac account: 93
// file-sharing groups) falls inside a 20-hook-call span. Every command the
// refresh starts is a gateway process plus its process-group watchdog shell
// and the shell that one starts: three gateway execs a command. The merge
// base started one dsmemberutil a group, 282 execs, 14.1 more on each call
// of the span. The refresh now starts none, and every answer is the one the
// tool gives: the same groups listed and the same errors, whatever the
// search policy or a directory does between the reads, because no read was
// added and nothing is skipped.
func TestGAP0326GroupRefreshStartsNoMembershipProcess(t *testing.T) {
	for _, tool := range []string{darwinDSMemberUtil, darwinID} {
		if err := validateTrustedTool(tool); err != nil {
			t.Skip(err)
		}
	}
	previousMember, previousNamed := openDirectoryUIDMember, lookupNamedGroupGID
	t.Cleanup(func() { openDirectoryUIDMember, lookupNamedGroupGID = previousMember, previousNamed })
	lookupNamedGroupGID = func(_ context.Context, name string) (int, bool, error) {
		if name == "dc-nested" {
			return 7000, true, nil
		}
		return 0, false, nil
	}

	const uid, namesakeGroup, nestedGroup = 511, 80, 7000
	ids := []string{"20", "12", "61"}
	for gid := 701; gid <= 792; gid++ {
		ids = append(ids, strconv.Itoa(gid))
	}
	member := map[uint32]bool{nestedGroup: true}
	for _, gid := range ids {
		n, _ := strconv.Atoi(gid)
		member[uint32(n)] = true
	}
	// A list os/user gave while a directory account named like the local one
	// was bound: it holds the namesake's group 80, which the uid is not in.
	stale := append(slices.Clone(ids), strconv.Itoa(namesakeGroup))
	account := &user.User{Username: "dcuser", Uid: strconv.Itoa(uid), Gid: "20"}

	type outcome struct {
		groups   []string
		err      bool
		commands int
	}
	// answer is Open Directory: the tool prints it, the in-process call
	// returns it.
	refresh := func(t *testing.T, inProcess bool, list []string, named []string, answer func(gid uint32) (bool, error)) outcome {
		var mu sync.Mutex
		commands := 0
		tool := func(ctx context.Context, path string, args []string, _ ...outputFilter) (commandResult, error) {
			mu.Lock()
			commands++
			mu.Unlock()
			if path != darwinDSMemberUtil || len(args) != 5 || args[0] != "checkmembership" || args[2] != strconv.Itoa(uid) {
				return commandResult{}, fmt.Errorf("unexpected command %s %q", path, args)
			}
			gid, _ := strconv.ParseUint(args[4], 10, 32)
			is, err := answer(uint32(gid))
			if err != nil {
				return commandResult{exitCode: 1}, nil
			}
			if is {
				return commandResult{stdout: []byte("user is a member of the group\n")}, nil
			}
			return commandResult{stdout: []byte("user is not a member of the group\n")}, nil
		}
		runner := tool
		if inProcess {
			openDirectoryUIDMember = func(u, gid uint32) (bool, error) {
				if u != uid {
					return false, fmt.Errorf("asked for uid %d", u)
				}
				return answer(gid)
			}
			runner = inProcessMembership(tool)
		}
		got, err := platformAccountGroupIDs(context.Background(), runner, account, list, nil, named)
		slices.Sort(got)
		return outcome{groups: got, err: err != nil, commands: commands}
	}

	known := func(gid uint32) (bool, error) { return member[gid], nil }
	for _, tc := range []struct {
		name   string
		list   []string
		named  []string
		answer func(uint32) (bool, error)
	}{
		{"95 groups", ids, nil, known},
		{"namesake list", stale, nil, known},
		{"named nested group", ids, []string{"dc-nested"}, known},
		{"Open Directory fails for one group", ids, nil, func(gid uint32) (bool, error) {
			if gid == 750 {
				return false, errors.New("opendirectoryd unavailable")
			}
			return member[gid], nil
		}},
		{"membership removed", ids, nil, func(gid uint32) (bool, error) { return member[gid] && gid != 701, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := refresh(t, false, tc.list, tc.named, tc.answer)
			head := refresh(t, true, tc.list, tc.named, tc.answer)
			if !slices.Equal(base.groups, head.groups) || base.err != head.err {
				t.Fatalf("in process: %v (error %t); dsmemberutil: %v (error %t)", head.groups, head.err, base.groups, base.err)
			}
			if head.commands != 0 {
				t.Fatalf("the refresh started %d commands, want none", head.commands)
			}
			if !base.err && base.commands < len(tc.list)-1 {
				t.Fatalf("the tool path ran %d checks for %d groups", base.commands, len(tc.list))
			}
			const spanCalls, execsPerCommand = 20, 3
			t.Logf("refresh in a %d-call span: %.1f gateway execs per call (tool path %.1f)",
				spanCalls, float64(head.commands*execsPerCommand)/spanCalls, float64(base.commands*execsPerCommand)/spanCalls)
		})
	}
}

// A late answer is an error under the tool's bound, as a dsmemberutil that
// outlived it was, and the caller's deadline still ends the refresh.
func TestGAP0326InProcessMembershipKeepsTheDeadline(t *testing.T) {
	previous := openDirectoryUIDMember
	t.Cleanup(func() { openDirectoryUIDMember = previous })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	openDirectoryUIDMember = func(uint32, uint32) (bool, error) {
		<-release
		return true, nil
	}
	runner := inProcessMembership(func(context.Context, string, []string, ...outputFilter) (commandResult, error) {
		return commandResult{}, errors.New("no command expected")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := runner(ctx, darwinDSMemberUtil, []string{"checkmembership", "-u", "511", "-g", "701"})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late answer = %v, want a deadline error", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("late answer took %s", elapsed)
	}
	// Anything but the uid membership check still runs as a command.
	ran := false
	runner = inProcessMembership(func(context.Context, string, []string, ...outputFilter) (commandResult, error) {
		ran = true
		return commandResult{}, nil
	})
	for _, args := range [][]string{
		{"flushcache"},
		{"checkmembership", "-U", "dcuser", "-g", "701"},
		{"checkmembership", "-u", "511", "-G", "staff"},
		{"checkmembership", "-u", "-1", "-g", "701"},
	} {
		ran = false
		if _, err := runner(context.Background(), darwinDSMemberUtil, args); err != nil || !ran {
			t.Fatalf("%q: ran %t, %v", args, ran, err)
		}
	}
}

// A native call cannot be cancelled. In a stalled directory the calls that
// outlive their bound keep their slots, so repeated refreshes leave at most
// cap(nativeMembershipSlots) calls outstanding; past that, checks run as the
// cancellable dsmemberutil process, as on the merge base. Every refresh
// fails as the merge base's does, and the native path comes back once the
// directory answers (review 1 of r108-g326c).
func TestGAP0326StalledDirectoryKeepsNativeCallsBounded(t *testing.T) {
	if err := validateTrustedTool(darwinDSMemberUtil); err != nil {
		t.Skip(err)
	}
	previousMember, previousSlots := openDirectoryUIDMember, nativeMembershipSlots
	t.Cleanup(func() { openDirectoryUIDMember, nativeMembershipSlots = previousMember, previousSlots })
	nativeMembershipSlots = make(chan struct{}, cap(previousSlots))
	limit := int32(cap(nativeMembershipSlots))

	var inFlight, most atomic.Int32
	release := make(chan struct{})
	stalled := true
	var stallMu sync.Mutex
	openDirectoryUIDMember = func(uint32, uint32) (bool, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		stallMu.Lock()
		wait := stalled
		stallMu.Unlock()
		if wait {
			<-release
		}
		return true, nil
	}
	var commands atomic.Int32
	// The dsmemberutil process of a stalled directory: it never answers and
	// ends when its context does, as exec.CommandContext kills it.
	tool := func(ctx context.Context, path string, args []string, _ ...outputFilter) (commandResult, error) {
		if path != darwinDSMemberUtil || len(args) != 5 {
			return commandResult{}, fmt.Errorf("unexpected command %s %q", path, args)
		}
		commands.Add(1)
		<-ctx.Done()
		return commandResult{}, ctx.Err()
	}
	ids := []string{"20"}
	for gid := 701; gid <= 794; gid++ {
		ids = append(ids, strconv.Itoa(gid))
	}
	account := &user.User{Username: "dcuser", Uid: "511", Gid: "20"}
	refresh := func(runner commandRunner) ([]string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		return platformAccountGroupIDs(ctx, runner, account, ids, nil, nil)
	}

	for i := range 6 {
		baseGroups, baseErr := refresh(tool)
		headGroups, headErr := refresh(inProcessMembership(tool))
		if baseErr == nil || headErr == nil || baseGroups != nil || headGroups != nil {
			t.Fatalf("refresh %d: base (%v, %v), head (%v, %v); want both to fail", i, baseGroups, baseErr, headGroups, headErr)
		}
		if n := inFlight.Load(); n > limit {
			t.Fatalf("refresh %d left %d native calls outstanding, more than %d", i, n, limit)
		}
	}
	if most.Load() > limit {
		t.Fatalf("%d native calls were in flight at once, more than %d", most.Load(), limit)
	}
	t.Logf("after 6 stalled refreshes: %d native calls outstanding (limit %d), %d dsmemberutil fallbacks", inFlight.Load(), limit, commands.Load())

	// The directory answers again: the stuck calls return, their slots free,
	// and the next refresh is native again with no process.
	stallMu.Lock()
	stalled = false
	stallMu.Unlock()
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for (inFlight.Load() != 0 || len(nativeMembershipSlots) != 0) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if inFlight.Load() != 0 || len(nativeMembershipSlots) != 0 {
		t.Fatalf("after the stall: %d calls, %d slots still held", inFlight.Load(), len(nativeMembershipSlots))
	}
	commands.Store(0)
	got, err := platformAccountGroupIDs(context.Background(), inProcessMembership(tool), account, ids, nil, nil)
	if err != nil || len(got) != len(ids) || commands.Load() != 0 {
		t.Fatalf("after the stall: %d groups, %v, %d commands; want %d, nil, 0", len(got), err, commands.Load(), len(ids))
	}
}
