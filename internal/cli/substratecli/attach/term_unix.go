// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package attach

import (
	"os"
	"os/signal"
	"syscall"
)

// watch signals on the returned channel on every SIGWINCH.
func (t *terminal) watch(stop <-chan struct{}) <-chan struct{} {
	ch := make(chan struct{}, 1)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	go func() {
		defer t.guard()
		defer signal.Stop(sig)
		for {
			select {
			case <-stop:
				return
			case <-sig:
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return ch
}

// enableVT is a no-op: unix terminals speak VT already.
func enableVT(in, out *os.File) func() { return func() {} }
