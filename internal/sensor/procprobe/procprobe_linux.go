// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package procprobe

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// maxCmdlineBytes bounds a single /proc/<pid>/cmdline read. A process can set
// an arbitrarily long argv, and the runtime plane only needs enough of it to
// recognise a framework or an exfiltration command.
const maxCmdlineBytes = 16 << 10

// snapshot reads /proc directly.
//
// Deliberately not shelling out to ps: /proc is the only dependency, so this
// works unchanged on a minimal container or cloud image that ships no
// procps-ng, and it avoids spawning a subprocess on every poll of a sensor
// running as root.
func snapshot() ([]Process, int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0, err
	}
	clockTicks := clockTicksPerSecond()
	pageSize := int64(os.Getpagesize())
	bootTime := bootInstant()

	rows := make([]Process, 0, len(entries))
	skipped := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || pid <= 0 {
			continue
		}
		row, ok := readProcess(pid, clockTicks, pageSize, bootTime)
		if !ok {
			// Either the process exited between ReadDir and here -- the normal
			// case, and not interesting -- or this run is not allowed to read
			// it. Both are counted so an unprivileged run can report coverage.
			skipped++
			continue
		}
		rows = append(rows, row)
	}
	return rows, skipped, nil
}

func readProcess(pid int, clockTicks, pageSize int64, bootTime time.Time) (Process, bool) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	statBytes, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return Process{}, false
	}
	row, ok := parseStat(statBytes, clockTicks, pageSize, bootTime)
	if !ok {
		return Process{}, false
	}
	row.PID = pid
	row.Cmdline = readCmdline(filepath.Join(base, "cmdline"))
	row.Name = untruncateComm(row.Name, row.Cmdline)
	row.User = ownerOf(base)
	return row, true
}

// untruncateComm recovers a full executable name that /proc/<pid>/stat cut off.
//
// The kernel caps comm at TASK_COMM_LEN-1 = 15 bytes, so ollama_llama_server
// arrives as ollama_llama_se and text-generation-server as text-generation.
// Both are entries in the local-model runtime table, matched by exact name, so
// the two largest local inference servers on Linux were invisible to plane A
// -- and to every other check keyed on the process name.
//
// argv[0] is not trustworthy on its own: any process can set it to anything.
// So this only ever lengthens a name it already agrees with. If argv[0]'s
// basename does not start with comm, comm wins and nothing is renamed.
func untruncateComm(comm, cmdline string) string {
	if comm == "" || cmdline == "" || len(comm) < commTruncationLimit {
		return comm
	}
	argv0, _, _ := strings.Cut(cmdline, " ")
	base := filepath.Base(strings.TrimSpace(argv0))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return comm
	}
	if len(base) <= len(comm) || !strings.HasPrefix(base, comm) {
		return comm
	}
	return base
}

// commTruncationLimit is TASK_COMM_LEN-1: the number of bytes the kernel keeps
// of a process name in /proc/<pid>/stat. A comm of exactly this length is the
// only case where truncation is possible.
const commTruncationLimit = 15

// parseStat decodes /proc/<pid>/stat.
//
// The comm field is parenthesised and may itself contain spaces and
// parentheses, so the split is anchored on the LAST ')' rather than on
// whitespace. A process named "a) 1 2 3 (b" is a real and trivially
// constructed way to desynchronise a naive field split, and every field after
// it -- including ppid and the CPU counters -- would then be read from the
// wrong offset.
func parseStat(raw []byte, clockTicks, pageSize int64, bootTime time.Time) (Process, bool) {
	open := bytes.IndexByte(raw, '(')
	closeIdx := bytes.LastIndexByte(raw, ')')
	if open < 0 || closeIdx < open {
		return Process{}, false
	}
	comm := string(raw[open+1 : closeIdx])
	rest := strings.Fields(string(raw[closeIdx+1:]))
	// rest[0] is state; fields are 1-indexed from state == field 3 in proc(5).
	// ppid is field 4, utime 14, stime 15, rss 24.
	// starttime is field 22, so offset 19 from state.
	const (
		offsetPPID      = 1
		offsetUTime     = 11
		offsetSTime     = 12
		offsetStartTime = 19
		offsetRSS       = 21
	)
	if len(rest) <= offsetRSS {
		return Process{}, false
	}
	ppid, err := strconv.Atoi(rest[offsetPPID])
	if err != nil {
		return Process{}, false
	}
	utime, _ := strconv.ParseInt(rest[offsetUTime], 10, 64)
	stime, _ := strconv.ParseInt(rest[offsetSTime], 10, 64)
	rssPages, _ := strconv.ParseInt(rest[offsetRSS], 10, 64)
	startTicks, _ := strconv.ParseInt(rest[offsetStartTime], 10, 64)

	cpu := time.Duration(0)
	if clockTicks > 0 {
		// Divide before scaling. Multiplying ticks by 1e9 first overflows
		// int64 at roughly 9.2e9 ticks -- about 2.9 years of CPU time at
		// USER_HZ 100, which a busy many-core process reaches in weeks, not
		// years. After the wrap CPUTime is negative or arbitrary, and the
		// delta plane A compares against the inference threshold is wrong in
		// whichever direction the wrap landed.
		ticks := utime + stime
		cpu = time.Duration(ticks/clockTicks)*time.Second +
			time.Duration((ticks%clockTicks)*int64(time.Second)/clockTicks)
	}
	// starttime is measured in clock ticks since boot, so it needs the boot
	// instant to become an absolute time. Left zero when either is unknown
	// rather than guessed: a wrong start time is worse than none, because
	// the correlator would use it to reject a legitimate match.
	var started time.Time
	if clockTicks > 0 && startTicks > 0 && !bootTime.IsZero() {
		started = bootTime.Add(
			time.Duration(startTicks/clockTicks)*time.Second +
				time.Duration((startTicks%clockTicks)*int64(time.Second)/clockTicks))
	}
	return Process{
		PPID: ppid, Name: comm, CPUTime: cpu, RSSBytes: rssPages * pageSize,
		StartedAt: started,
	}, true
}

func readCmdline(path string) string {
	handle, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer handle.Close()
	// Read to EOF rather than trusting one call. io.Reader may return fewer
	// bytes than the buffer holds, and accepting the first result cuts argv
	// mid-token -- which silently loses the framework identity that lives in
	// a later argument, the whole reason argv is read at all.
	buffer := make([]byte, maxCmdlineBytes)
	read, err := io.ReadFull(handle, buffer)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return ""
	}
	if read <= 0 {
		return ""
	}
	// /proc/<pid>/cmdline is NUL-separated with a trailing NUL.
	fields := bytes.Split(bytes.TrimRight(buffer[:read], "\x00"), []byte{0})
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(field) > 0 {
			parts = append(parts, string(field))
		}
	}
	return strings.Join(parts, " ")
}

// bootInstant reads btime from /proc/stat: the wall-clock second the kernel
// booted. /proc/<pid>/stat reports a process start as ticks since that
// instant, so without it the number cannot be turned into a time.
//
// Returns the zero time on any failure. The caller leaves StartedAt unset in
// that case rather than substituting a plausible value.
func bootInstant() time.Time {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		value, ok := strings.CutPrefix(line, "btime ")
		if !ok {
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil || seconds <= 0 {
			return time.Time{}
		}
		return time.Unix(seconds, 0)
	}
	return time.Time{}
}
