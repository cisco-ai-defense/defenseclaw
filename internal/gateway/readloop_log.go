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

package gateway

import (
	"fmt"
	"os"
	"sync"
)

// The WebSocket read loop must stay responsive: if stderr is a slow writer
// (e.g. daemon mode appending both streams to one log file), synchronous
// fmt.Fprintf(os.Stderr) can block and stall RPC delivery (including connect).
// readLoopStderrQueue is now ReadLoopStderrQueueSize in constants.go

var readLoopStderrOnce sync.Once
var readLoopStderrCh chan string

func startReadLoopStderrDrainer() {
	readLoopStderrOnce.Do(func() {
		readLoopStderrCh = make(chan string, ReadLoopStderrQueueSize)
		go func() {
			for line := range readLoopStderrCh {
				_, _ = fmt.Fprint(os.Stderr, line)
			}
		}()
	})
}

// readLoopLogf queues one log line for stderr (adds newline if missing).
// Used only from readLoop so inbound frames keep being read even if stderr blocks.
func readLoopLogf(format string, args ...interface{}) {
	startReadLoopStderrDrainer()
	s := fmt.Sprintf(format, args...)
	if len(s) == 0 || s[len(s)-1] != '\n' {
		s += "\n"
	}
	readLoopStderrCh <- s
}
