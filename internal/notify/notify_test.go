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

//go:build darwin || linux

package notify

import (
	"bytes"
	"strings"
	"testing"
)

func TestSendDoesNotPanic(t *testing.T) {
	// Send may or may not succeed depending on OS capabilities,
	// but it must never panic.
	err := Send("Test", "test message")
	_ = err // OK to fail (e.g. no display server in CI)
}

func TestFallbackWriter(t *testing.T) {
	var buf bytes.Buffer
	old := fallbackWriter
	fallbackWriter = &buf
	defer func() { fallbackWriter = old }()

	err := Send("", "")
	if err != nil && !strings.Contains(buf.String(), "[defenseclaw-watchdog]") {
		t.Fatalf("expected fallback line when send fails, got buf=%q err=%v", buf.String(), err)
	}
}
