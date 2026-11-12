// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyWindowResize delivers terminal resizes (SIGWINCH) to sig.
func notifyWindowResize(sig chan<- os.Signal) { signal.Notify(sig, syscall.SIGWINCH) }
