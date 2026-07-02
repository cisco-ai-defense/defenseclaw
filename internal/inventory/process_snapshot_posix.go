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

//go:build !windows

package inventory

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// platformProcessSnapshot preserves the existing macOS/Linux ps path.
func platformProcessSnapshot() ([]processInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=,user=,comm=,etime=")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var infos []processInfo
	for _, line := range strings.Split(out.String(), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		infos = append(infos, processInfo{
			PID: pid, PPID: ppid, User: fields[2],
			Comm:      strings.ToLower(filepath.Base(strings.Join(fields[3:len(fields)-1], " "))),
			StartedAt: now.Add(-parsePsEtime(fields[len(fields)-1])),
		})
	}
	return infos, nil
}

func parsePsEtime(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	days := 0
	if idx := strings.IndexByte(value, '-'); idx >= 0 {
		d, err := strconv.Atoi(value[:idx])
		if err != nil {
			return 0
		}
		days, value = d, value[idx+1:]
	}
	parts := strings.Split(value, ":")
	if len(parts) == 0 || len(parts) > 3 {
		return 0
	}
	values := make([]int, len(parts))
	for i := range parts {
		values[i], _ = strconv.Atoi(parts[i])
	}
	var hours, minutes, seconds int
	switch len(values) {
	case 3:
		hours, minutes, seconds = values[0], values[1], values[2]
	case 2:
		minutes, seconds = values[0], values[1]
	case 1:
		seconds = values[0]
	}
	return time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
}
