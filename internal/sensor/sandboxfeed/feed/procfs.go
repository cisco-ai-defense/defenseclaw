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

package feed

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procReadLimit bounds one /proc file read (status is about 1.5 KB).
const procReadLimit = 16 << 10

// HostProc reads host processes from /proc (Root, for tests).
type HostProc struct {
	Root string
}

// NSPid returns the pid a process has in its innermost pid namespace (the
// last NSpid value of its status) and its start in clock ticks since boot
// (field 22 of its stat). The start is read before and after the status and
// must not change, so the two belong to the same process.
func (p HostProc) NSPid(hostPID int) (int, int64, bool) {
	if hostPID <= 0 {
		return 0, 0, false
	}
	dir := filepath.Join(p.root(), strconv.Itoa(hostPID))
	before, ok := startTicks(filepath.Join(dir, "stat"))
	if !ok {
		return 0, 0, false
	}
	nsPID, ok := innermostPID(filepath.Join(dir, "status"))
	if !ok {
		return 0, 0, false
	}
	after, ok := startTicks(filepath.Join(dir, "stat"))
	if !ok || after != before {
		return 0, 0, false
	}
	return nsPID, before, true
}

func (p HostProc) root() string {
	if p.Root == "" {
		return "/proc"
	}
	return p.Root
}

func readProc(path string) ([]byte, bool) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, procReadLimit))
	return data, err == nil
}

// startTicks reads field 22 (starttime) of a stat file. The comm field (2)
// may hold spaces and parentheses, so the fields are counted from the last
// closing parenthesis: field 3 follows it.
func startTicks(path string) (int64, bool) {
	data, ok := readProc(path)
	if !ok {
		return 0, false
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data[end+1:]))
	const starttime = 22 - 3
	if len(fields) <= starttime {
		return 0, false
	}
	ticks, err := strconv.ParseInt(fields[starttime], 10, 64)
	return ticks, err == nil && ticks >= 0
}

// innermostPID reads the last value of a status file's NSpid line.
func innermostPID(path string) (int, bool) {
	data, ok := readProc(path)
	if !ok {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, found := strings.CutPrefix(line, "NSpid:")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		pid, err := strconv.Atoi(fields[len(fields)-1])
		return pid, err == nil && pid > 0
	}
	return 0, false
}
