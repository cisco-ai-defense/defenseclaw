// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

import "syscall"

// procTree is not measured off Linux (actors run Linux): only the agent's
// output counts as progress there, and a stall stops its process group.
type procTree struct{}

func newProcTree(int) *procTree             { return &procTree{} }
func (*procTree) asAgent(*separation)       {}
func (*procTree) usage() (Usage, bool)      { return Usage{}, false }
func (*procTree) signal(sig syscall.Signal) {}
