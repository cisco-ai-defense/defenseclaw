// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package attach

import "time"

// pollSize signals on the returned channel when the size changes, checking
// every interval (Windows has no SIGWINCH).
func (t *terminal) pollSize(stop <-chan struct{}, every time.Duration) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		defer t.guard()
		tick := time.NewTicker(every)
		defer tick.Stop()
		last, _ := t.size()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			if sz, ok := t.size(); ok && sz != last {
				last = sz
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return ch
}
