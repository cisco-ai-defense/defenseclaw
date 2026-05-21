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

//go:build windows

package cli

import (
	"os"
	"syscall"
)

// sidecarSignals returns the signals the sidecar listens for on Windows.
// Only SIGINT and SIGTERM are meaningful on Windows; Unix-specific signals
// (SIGHUP, SIGQUIT, SIGPIPE, SIGUSR1, SIGUSR2) are unavailable.
func sidecarSignals(_ bool) []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM}
}

// isSigPipe always returns false on Windows (SIGPIPE does not exist).
func isSigPipe(_ os.Signal) bool { return false }
