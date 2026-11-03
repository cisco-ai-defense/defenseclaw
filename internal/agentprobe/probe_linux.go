// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agentprobe

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const procReadLimit = 64 << 10

type process struct {
	pid, ppid int
	start     uint64
	uid       uint32
	argv      []string
	exe       string
}

func processFile(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, procReadLimit+1))
	if err != nil || len(data) == 0 || len(data) > procReadLimit {
		return nil, false
	}
	return data, true
}

func readProcess(root string, pid int, rootEnumerator bool) (process, bool) {
	if pid <= 1 {
		return process{}, false
	}
	dir := filepath.Join(root, strconv.Itoa(pid))
	status, ok := processFile(filepath.Join(dir, "status"))
	if !ok {
		return process{}, false
	}
	var uid uint32
	uidKnown := false
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		if value, found := bytes.CutPrefix(line, []byte("Uid:")); found {
			fields := strings.Fields(string(value))
			if len(fields) != 4 {
				return process{}, false
			}
			parsed, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return process{}, false
			}
			uid, uidKnown = uint32(parsed), true
			break
		}
	}
	if !uidKnown {
		return process{}, false
	}
	stat, ok := processFile(filepath.Join(dir, "stat"))
	if !ok {
		return process{}, false
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return process{}, false
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return process{}, false
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil || parent < 0 {
		return process{}, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return process{}, false
	}
	cmdline, ok := processFile(filepath.Join(dir, "cmdline"))
	if !ok || cmdline[len(cmdline)-1] != 0 {
		return process{}, false
	}
	parts := bytes.Split(cmdline[:len(cmdline)-1], []byte{0})
	argv := make([]string, len(parts))
	for i, part := range parts {
		if len(part) == 0 {
			return process{}, false
		}
		argv[i] = string(part)
	}
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		if !rootEnumerator || !os.IsPermission(err) {
			return process{}, false
		}
	} else if !filepath.IsAbs(exe) {
		return process{}, false
	}
	return process{pid: pid, ppid: parent, start: start, uid: uid, argv: argv, exe: exe}, true
}

func sameProcess(root string, first process, rootEnumerator bool) bool {
	again, ok := readProcess(root, first.pid, rootEnumerator)
	if !ok || again.ppid != first.ppid || again.start != first.start ||
		again.uid != first.uid || again.exe != first.exe || len(again.argv) != len(first.argv) {
		return false
	}
	for i := range first.argv {
		if again.argv[i] != first.argv[i] {
			return false
		}
	}
	return true
}

func exactPrefix(argv []string, args ...string) bool {
	if len(argv) < len(args)+1 {
		return false
	}
	for i, arg := range args {
		if argv[i+1] != arg {
			return false
		}
	}
	return true
}

func versionCommand(p process) bool {
	if len(p.argv) == 2 && filepath.Base(p.argv[0]) == Hermes && p.argv[1] == "--version" &&
		filepath.Base(p.exe) == Hermes {
		return true
	}
	if len(p.argv) == 3 && strings.HasPrefix(filepath.Base(p.argv[0]), "python") &&
		strings.HasPrefix(filepath.Base(p.exe), "python") && filepath.IsAbs(p.argv[1]) &&
		filepath.Base(p.argv[1]) == Hermes && p.argv[2] == "--version" {
		return true
	}
	if len(p.argv) != 5 || !strings.HasPrefix(filepath.Base(p.argv[0]), "python") ||
		!strings.HasPrefix(filepath.Base(p.exe), "python") || p.argv[1] != "-I" ||
		p.argv[2] != "-c" || p.argv[4] != "--version" {
		return false
	}
	return strings.Contains(p.argv[3], "from hermes_cli.main import main")
}

func probeEnvironment(root string, p process, accountHome string) bool {
	environ, ok := processFile(filepath.Join(root, strconv.Itoa(p.pid), "environ"))
	if !ok || environ[len(environ)-1] != 0 {
		return false
	}
	values := map[string]string{}
	for _, entry := range bytes.Split(environ[:len(environ)-1], []byte{0}) {
		key, value, found := bytes.Cut(entry, []byte{'='})
		if !found || len(key) == 0 {
			return false
		}
		switch string(key) {
		case "HOME", "PATH", "LANG", "NO_COLOR", "TERM", "CI", "HERMES_HOME", "TMPDIR", EnvName:
			if _, duplicate := values[string(key)]; duplicate {
				return false
			}
			values[string(key)] = string(value)
		default:
			return false
		}
	}
	home := values["HERMES_HOME"]
	if len(values) != 9 || values[EnvName] != Hermes || values["HOME"] != accountHome ||
		values["LANG"] != "C" || values["NO_COLOR"] != "1" || values["TERM"] != "dumb" || values["CI"] != "1" ||
		home == "" || home != values["TMPDIR"] || !filepath.IsAbs(home) ||
		filepath.Clean(home) != home || !strings.HasPrefix(filepath.Base(home), "dc-agent-probe-") {
		return false
	}
	info, err := os.Lstat(home)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == p.uid
}

// managedHermesVersion identifies a version command through its process
// lineage, command, bounded environment, and stable PID start times.
func managedHermesVersion(procRoot string, pid int, accountHome string) (process, bool) {
	child, ok := readProcess(procRoot, pid, false)
	if !ok || !versionCommand(child) || !probeEnvironment(procRoot, child, accountHome) {
		return process{}, false
	}
	worker, ok := readProcess(procRoot, child.ppid, false)
	if !ok || worker.uid != child.uid || worker.start > child.start ||
		len(worker.argv) != 4 || !exactPrefix(worker.argv, "enterprise", "hooks", "apply-target") {
		return process{}, false
	}
	// An account worker cannot always read the executable link of a root
	// process. Its root-owned parent is checked by stable PID, UID and exact
	// command line; when the link is readable, it must match the worker.
	enumerator, ok := readProcess(procRoot, worker.ppid, true)
	if !ok || enumerator.uid != 0 || enumerator.start > worker.start ||
		filepath.Base(enumerator.argv[0]) != "defenseclaw-gateway" ||
		(enumerator.exe != "" && worker.exe != enumerator.exe) || worker.argv[0] != enumerator.argv[0] ||
		len(enumerator.argv) != 8 || !exactPrefix(enumerator.argv, "enterprise", "hooks", "enumerate", "--manifest") ||
		!filepath.IsAbs(enumerator.argv[5]) || enumerator.argv[6] != "--interval" {
		return process{}, false
	}
	interval, err := time.ParseDuration(enumerator.argv[7])
	if err != nil || interval <= 0 {
		return process{}, false
	}
	if enumerator.exe == "" {
		installed, err := filepath.EvalSymlinks(enumerator.argv[0])
		if err != nil || installed != worker.exe {
			return process{}, false
		}
	}
	if !sameProcess(procRoot, child, false) || !sameProcess(procRoot, worker, false) ||
		!sameProcess(procRoot, enumerator, true) {
		return process{}, false
	}
	return child, true
}

// WaitManagedHermesVersion waits for a proven version command to leave the
// process table. Callers rescan afterward; no live process is exempted from
// coverage or account-home evidence.
func WaitManagedHermesVersion(procRoot string, pid int, accountHome string, maxWait time.Duration) bool {
	return waitManagedHermesVersion(procRoot, pid, accountHome, maxWait, nil)
}

func waitManagedHermesVersion(procRoot string, pid int, accountHome string, maxWait time.Duration, onProven func()) bool {
	if _, ok := managedHermesVersion(procRoot, pid, accountHome); !ok {
		return false
	}
	if onProven != nil {
		onProven()
	}
	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	for {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return true
		}
		select {
		case <-timer.C:
			return false
		case <-tick.C:
		}
	}
}
