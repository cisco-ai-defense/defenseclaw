// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package relay

import "os/exec"

// Actors are Linux: elsewhere there is no other user to run the agent as.
type agentCred = *struct{}

func (*separation) asAgent(*exec.Cmd) {}
