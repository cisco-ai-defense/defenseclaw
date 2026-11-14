// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

import (
	"errors"
	"os"
	"os/exec"
)

// Actors are Linux; the relay serves terminals only there.
func startPTY(*exec.Cmd, uint16, uint16) (*os.File, error) {
	return nil, errors.New("the actor relay serves terminals only on Linux")
}

func setSize(*os.File, uint16, uint16) error { return errors.New("not supported") }
