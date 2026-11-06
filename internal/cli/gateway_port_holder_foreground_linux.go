// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func sameHomeGatewayProcessPlatform(pid int, home, executable string) bool {
	expected, err := os.Stat(executable)
	if err != nil {
		return false
	}
	actual, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil || !os.SameFile(expected, actual) {
		return false
	}
	environment, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil || len(environment) == 0 || len(environment) > 4*1024*1024 {
		return false
	}
	count := 0
	for _, entry := range strings.Split(string(environment), "\x00") {
		if !strings.HasPrefix(entry, "DEFENSECLAW_HOME=") {
			continue
		}
		value := strings.TrimPrefix(entry, "DEFENSECLAW_HOME=")
		if !filepath.IsAbs(value) || filepath.Clean(value) != filepath.Clean(home) {
			return false
		}
		count++
	}
	return count == 1
}
