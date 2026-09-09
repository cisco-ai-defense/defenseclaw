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

//go:build darwin

package procprobe

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// snapshotTimeout bounds one ps invocation. A hung ps must not stall the poll
// loop, because a stalled poll looks exactly like a quiet host.
const snapshotTimeout = 10 * time.Second

// snapshot shells out to ps.
//
// macOS has no /proc, and the sysctl KERN_PROC route needs cgo for the struct
// layout. ps(1) is part of the base system, returns the whole process table to
// an unprivileged caller, and is the same source the upstream detector used.
//
// The format is deliberately ordered with args last: it is the only field that
// can contain spaces, so the five fixed fields split on whitespace and the
// remainder is argv verbatim.
//
// comm is deliberately not requested. The kernel-backed short process name is
// truncated to 16 bytes on Darwin, so "/usr/libexec/logd" arrives as
// "/usr/libexec/log" and a basename taken from it is wrong in exactly the
// cases -- long tool names -- where identification matters. The executable
// name is recovered from the first argv token instead.
func snapshot() ([]Process, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), snapshotTimeout)
	defer cancel()

	cmd := processutil.CommandContext(ctx, "/bin/ps", "-Ao", "pid=,ppid=,rss=,time=,user=,args=")
	output, err := cmd.Output()
	if err != nil {
		return nil, 0, err
	}

	rows := make([]Process, 0, 512)
	skipped := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		row, ok := parsePSLine(scanner.Text())
		if !ok {
			skipped++
			continue
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return rows, skipped, err
	}
	return rows, skipped, nil
}

// parsePSLine decodes one row of the ps format above: five whitespace-
// delimited fixed fields, then argv verbatim.
func parsePSLine(line string) (Process, bool) {
	rest := strings.TrimLeft(line, " \t")
	values := make([]string, 0, 5)
	for len(values) < 5 {
		index := strings.IndexAny(rest, " \t")
		if index < 0 {
			return Process{}, false
		}
		values = append(values, rest[:index])
		rest = strings.TrimLeft(rest[index:], " \t")
	}
	pid, err := strconv.Atoi(values[0])
	if err != nil || pid <= 0 {
		return Process{}, false
	}
	ppid, err := strconv.Atoi(values[1])
	if err != nil {
		return Process{}, false
	}
	rssKB, err := strconv.ParseInt(values[2], 10, 64)
	if err != nil {
		return Process{}, false
	}
	cpu, ok := parsePSTime(values[3])
	if !ok {
		return Process{}, false
	}
	cmdline := strings.TrimSpace(rest)
	if cmdline == "" {
		return Process{}, false
	}
	if len(cmdline) > maxCmdlineBytes {
		cmdline = cmdline[:maxCmdlineBytes]
	}
	// The executable is the first argv token. A path with spaces would break
	// this, but argv[0] for such a binary is quoted by the kernel only in
	// contrived cases and ps does not preserve the quoting either way; taking
	// the first token matches what every other consumer of this format does.
	name := cmdline
	if index := strings.IndexAny(name, " \t"); index >= 0 {
		name = name[:index]
	}
	return Process{
		PID: pid, PPID: ppid, Name: baseName(name), Cmdline: cmdline,
		User: values[4], CPUTime: cpu, RSSBytes: rssKB * 1024,
	}, true
}

// parsePSTime decodes ps's cumulative CPU column, which is [[dd-]hh:]mm:ss.
func parsePSTime(value string) (time.Duration, bool) {
	days := 0
	if dash := strings.IndexByte(value, '-'); dash >= 0 {
		parsed, err := strconv.Atoi(value[:dash])
		if err != nil {
			return 0, false
		}
		days = parsed
		value = value[dash+1:]
	}
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, false
	}
	total := time.Duration(days) * 24 * time.Hour
	units := []time.Duration{time.Hour, time.Minute, time.Second}
	units = units[len(units)-len(parts):]
	for index, part := range parts {
		// The seconds field can carry a fraction on some formats.
		seconds, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return 0, false
		}
		total += time.Duration(seconds * float64(units[index]))
	}
	return total, true
}

func baseName(value string) string {
	if index := strings.LastIndexByte(value, '/'); index >= 0 {
		return value[index+1:]
	}
	return value
}

// maxCmdlineBytes bounds the argv retained per process.
const maxCmdlineBytes = 16 << 10
