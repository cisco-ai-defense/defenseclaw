// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"strconv"
	"strings"
)

func sameHomeGatewayProcessPlatform(pid int, home, executable string) bool {
	if !sameForegroundFile("/proc/"+strconv.Itoa(pid)+"/exe", executable) {
		return false
	}
	environment, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil || len(environment) == 0 || len(environment) > 4*1024*1024 {
		return false
	}
	processHome, ok := foregroundLaunchHome(strings.Split(string(environment), "\x00"))
	return ok && sameForegroundFile(processHome, home)
}
