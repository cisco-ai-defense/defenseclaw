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
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureStderr redirects os.Stderr for the duration of fn and
// returns everything that was written. Used to assert on the
// operator-facing log lines emitted by proxy helpers. The write end
// is closed before we read back from the pipe so io.ReadAll's
// goroutine can finish before we inspect the captured bytes.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	var (
		mu   sync.Mutex
		buf  strings.Builder
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		b, _ := io.ReadAll(r)
		mu.Lock()
		buf.Write(b)
		mu.Unlock()
	}()

	fn()
	_ = w.Close()
	<-done
	os.Stderr = orig
	mu.Lock()
	defer mu.Unlock()
	return buf.String()
}

// logVerdict is the workhorse used by both logPreCall and
// logPostCall; once it redacts correctly every caller benefits.
func TestLogVerdict_RedactsReasonAndFindingsByDefault(t *testing.T) {
	v := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Reason:   "matched secret: sk-ant-api03-abcdefghij1234567890abcdefghij",
		Findings: []string{
			"SEC-ANTHROPIC:API key sk-ant-api03-abcdefghij1234567890abcdefghij",
			"PII-SSN:123-45-6789",
		},
		ScannerSources: []string{"local-pattern", "cisco-ai-defense"},
	}

	out := captureStderr(t, func() {
		logVerdict(v.Severity, v.Action, v, 42*time.Millisecond)
	})

	if strings.Contains(out, "sk-ant-api03-abcdefghij1234567890abcdefghij") {
		t.Errorf("verdict log leaked Anthropic key: %s", out)
	}
	if strings.Contains(out, "123-45-6789") {
		t.Errorf("verdict log leaked SSN: %s", out)
	}
	// Rule IDs must still appear so operators know what tripped.
	if !strings.Contains(out, "SEC-ANTHROPIC") {
		t.Errorf("verdict log dropped rule ID SEC-ANTHROPIC: %s", out)
	}
	if !strings.Contains(out, "PII-SSN") {
		t.Errorf("verdict log dropped rule ID PII-SSN: %s", out)
	}
	// Scanner source enum is static metadata; must pass verbatim.
	if !strings.Contains(out, "local-pattern") {
		t.Errorf("verdict log dropped scanner source: %s", out)
	}
}

func TestLogVerdict_RevealHonored(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	v := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Reason:   "matched secret: sk-ant-api03-abcdefghij1234567890abcdefghij",
		Findings: []string{"SEC-ANTHROPIC:sk-ant-api03-abcdefghij1234567890abcdefghij"},
	}
	out := captureStderr(t, func() {
		logVerdict(v.Severity, v.Action, v, 10*time.Millisecond)
	})
	if !strings.Contains(out, "sk-ant-api03-abcdefghij1234567890abcdefghij") {
		t.Errorf("reveal flag failed to emit raw literal: %s", out)
	}
}

// NONE-severity verdicts must never embed verdict.Reason at all —
// we still assert that no literal ever leaks, since a stray
// message here would trip every other PII-scrubbing test suite.
func TestLogVerdict_NoneSeverityEmitsNoReason(t *testing.T) {
	v := &ScanVerdict{
		Action:   "allow",
		Severity: "NONE",
		Reason:   "sk-ant-api03-abcdefghij1234567890abcdefghij", // would leak if printed
	}
	out := captureStderr(t, func() {
		logVerdict(v.Severity, v.Action, v, 0)
	})
	if strings.Contains(out, "sk-ant-api03-") {
		t.Errorf("NONE branch leaked reason: %s", out)
	}
}
