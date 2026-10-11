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

package hookexec

import (
	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func connectionRefused(err error) bool {
	// net/http returns Winsock's WSAECONNREFUSED (10061) on native Windows.
	// Keep syscall.ECONNREFUSED as well so injected transports and wrapped
	// portable errors retain the same classification as other platforms.
	return errors.Is(err, windows.WSAECONNREFUSED) || errors.Is(err, syscall.ECONNREFUSED)
}

// hookDialTimeout outlasts the refusal Windows reports for a loopback port
// nobody listens on: it retries the SYN and returns WSAECONNREFUSED after
// about 2 s (2076 ms on Windows Server 2025). A 2 s dial timeout won that
// race, so a stopped per-user gateway read as a timeout and the hook never
// ran its cold start (GAP-0377).
const hookDialTimeout = 4 * time.Second
