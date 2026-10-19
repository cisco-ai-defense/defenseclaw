// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

// This fixed contributor payload is compiled with CGO_ENABLED=0. It is never
// installed or selected by customer execution. No arbitrary command or host
// path is accepted. Its only filesystem mutations are fixed guest canaries.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const sentinel = "fixed-public-native-peer-canary\n"

func main() {
	code, err := run()
	if err != nil {
		// Errors are fixed codes: do not print OS diagnostics, paths or env.
		fmt.Fprintln(os.Stderr, "FIXED_NATIVE_FAILURE "+err.Error())
		os.Exit(1)
	}
	os.Exit(code)
}

func refuse(code string) (int, error) { return 0, errors.New(code) }

func run() (int, error) {
	if len(os.Args) < 2 || len(os.Args) > 10 {
		return refuse("selector")
	}
	cwd, err := os.Getwd()
	if err != nil || cwd != "/work" {
		return refuse("cwd")
	}
	seal, err := fixedRead("/work/fixture-seal")
	if err != nil || string(seal) != sentinel || os.Getenv("DC_AXIS_FIXED_PAYLOAD") != "fixed-private-v1" {
		return refuse("fixture")
	}
	// Bubblewrap itself sets PWD after its final chdir. Require that exact
	// derived value in addition to the three explicitly supplied variables.
	allowed := []string{"HOME=/home", "TMPDIR=/tmp", "DC_AXIS_FIXED_PAYLOAD=fixed-private-v1", "PWD=/work"}
	environment := os.Environ()
	if len(environment) != len(allowed) {
		return refuse("environment_count")
	}
	for _, entry := range environment {
		if !slices.Contains(allowed, entry) {
			return refuse("extra_environment")
		}
	}
	for _, entry := range allowed {
		if !slices.Contains(environment, entry) {
			return refuse("missing_environment")
		}
	}
	mode := os.Args[1]
	if mode != "argv" && mode != "boundaries" && len(os.Args) != 2 {
		return refuse("arguments")
	}
	switch mode {
	case "argv":
		expected := []string{"argv", "", "a b", "a\"b", "tail\\", "λ-雪;$()`&|<>*?", "quoted space\\"}
		if !slices.Equal(os.Args[1:], expected) {
			return refuse("literal_argv")
		}
		fmt.Println("FIXED_NATIVE_ARGV")
		return 23, nil
	case "boundaries":
		if len(os.Args) != 3 || !fixedOutside(os.Args[2]) {
			return refuse("outside_fixture")
		}
		return boundaries(os.Args[2])
	case "stdio":
		fmt.Println("FIXED_NATIVE_INPUT_READY")
		input, readErr := io.ReadAll(io.LimitReader(os.Stdin, 1025))
		if readErr != nil || !bytes.Equal(input, []byte("fixed-public-input\x00\xff\n")) {
			return refuse("input_bytes_or_eof")
		}
		fmt.Println("FIXED_NATIVE_INPUT_EOF")
		fmt.Fprintln(os.Stderr, "FIXED_NATIVE_STDERR")
		return 23, nil
	case "exit23":
		fmt.Println("FIXED_NATIVE_EXIT23")
		return 23, nil
	case "wait":
		fmt.Println("FIXED_NATIVE_WAIT_READY")
		time.Sleep(time.Minute)
		return refuse("timeout_not_enforced")
	case "tree-parent", "tree-child", "tree-grandchild":
		return tree(mode)
	default:
		return refuse("selector")
	}
}

func fixedOutside(path string) bool {
	const prefix = "/tmp/dc-axis-native-peer-"
	const suffix = "/outside"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return false
	}
	identity := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	return len(identity) == 32 && strings.Trim(identity, "0123456789abcdef") == ""
}

func boundaries(outside string) (int, error) {
	var root unix.Statfs_t
	if err := unix.Statfs("/", &root); err != nil || root.Flags&unix.ST_RDONLY == 0 {
		return refuse("private_root_readonly")
	}
	if value, err := fixedRead("/readonly"); err != nil || string(value) != sentinel {
		return refuse("readonly_positive")
	}
	// Verify every grant to be mutated before the first positive write. The
	// host harness must also compare the exact held source identities/bytes.
	for _, path := range []string{"/home/fixture-seal", "/tmp/fixture-seal"} {
		if value, err := fixedRead(path); err != nil || string(value) != sentinel {
			return refuse("private_write_fixture")
		}
	}
	for _, path := range []string{"/work/allowed-write", "/home/allowed-write", "/tmp/allowed-write"} {
		if err := writeNew(path, []byte(sentinel)); err != nil {
			return refuse("write_positive")
		}
	}
	// Negative tests only try to acquire access, then close any unexpected
	// handle. They never write, truncate or create an ungranted object even
	// when the very containment boundary under test is broken.
	if !negativeAccess("/readonly", unix.O_WRONLY, unix.EROFS, unix.EACCES) {
		return refuse("readonly_denial")
	}
	if !negativeAccess(outside+"/read-canary", unix.O_RDONLY, unix.ENOENT, unix.EACCES) {
		return refuse("outside_read_denial")
	}
	if !negativeAccess(outside+"/write-canary", unix.O_WRONLY, unix.ENOENT, unix.EACCES, unix.EROFS) {
		return refuse("outside_write_denial")
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6, unix.AF_UNIX} {
		for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
			descriptor, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, 0)
			if descriptor >= 0 {
				_ = unix.Close(descriptor)
			}
			if !errors.Is(err, unix.EPERM) {
				return refuse("offline_socket_denial")
			}
		}
	}
	if pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); !errors.Is(err, unix.EPERM) {
		if err == nil {
			_ = unix.Close(pair[0])
			_ = unix.Close(pair[1])
		}
		return refuse("offline_socketpair_denial")
	}
	fmt.Println("FIXED_NATIVE_BOUNDARIES")
	return 23, nil
}

func fixedRead(path string) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "fixed-canary")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(sentinel)) {
		return nil, errors.New("fixed_canary_type_or_size")
	}
	return io.ReadAll(io.LimitReader(file, int64(len(sentinel)+1)))
}

func negativeAccess(path string, mode int, expected ...error) bool {
	descriptor, err := unix.Open(path, mode|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if descriptor >= 0 {
		_ = unix.Close(descriptor)
	}
	for _, allowed := range expected {
		if errors.Is(err, allowed) {
			return true
		}
	}
	return false
}

func writeNew(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	return errors.Join(writeErr, file.Close())
}

// Pinned x/sys Getpgrp calls Getpgid(0) and discards its error. That is syscall
// 121 on amd64, outside the unchanged offline allowlist. Use allowed syscall 111
// directly and retain the errno in this precondition. The injected function is
// exercised only by inert tests; actual descendants supply unix.RawSyscall.
func fixedTreeGroup(raw func(uintptr, uintptr, uintptr, uintptr) (uintptr, uintptr, unix.Errno), pid int) bool {
	if pid <= 0 {
		return false
	}
	group, _, errno := raw(unix.SYS_GETPGRP, 0, 0, 0)
	return errno == 0 && group > 0 && group <= uintptr(1<<31-1) && group != uintptr(pid)
}

func tree(mode string) (int, error) {
	// Require EPERM without relaxing the pinned session-creation filter.
	// A group leader can also get EPERM naturally. Only the new positive-group,
	// nonleader descendants substantiate filter denial; parent EPERM is a
	// consistency check and is not counted as independent denial evidence.
	if mode != "tree-parent" && !fixedTreeGroup(unix.RawSyscall, os.Getpid()) {
		return refuse("tree_setsid_precondition")
	}
	if _, err := unix.Setsid(); !errors.Is(err, unix.EPERM) {
		return refuse("tree_setsid_denial")
	}
	if mode != "tree-grandchild" {
		next := "tree-child"
		if mode == "tree-child" {
			next = "tree-grandchild"
		}
		// A fixed guest image only. There is no PATH search or host executable.
		command := exec.Command("/.defenseclaw/payload", next)
		command.Env = os.Environ()
		command.Dir = "/work"
		command.Stdin = nil
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Start(); err != nil {
			return refuse("tree_spawn")
		}
		defer func() {
			_ = command.Process.Kill()
			_ = command.Wait()
		}()
	}
	heartbeat, err := os.OpenFile("/work/"+mode+".heartbeat", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return refuse("tree_heartbeat_create")
	}
	defer heartbeat.Close()
	if err := writeNew("/work/"+mode+".ready", []byte(sentinel)); err != nil {
		return refuse("tree_ready_write")
	}
	fmt.Println("FIXED_NATIVE_TREE_READY " + mode)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(time.Minute)
	defer deadline.Stop()
	for count := 1; ; count++ {
		select {
		case <-ticker.C:
			if _, err := heartbeat.WriteAt([]byte(fmt.Sprint(count)), 0); err != nil {
				return refuse("tree_heartbeat_write")
			}
		case <-deadline.C:
			return refuse("tree_cleanup_not_enforced")
		}
	}
}
