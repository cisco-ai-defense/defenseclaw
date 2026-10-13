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

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0381: a started gateway printed the local Splunk's web UI and where
// its password is whenever the bridge's env file held one, after `setup
// splunk --disable` stopped the container and after it was removed. The
// hint needs the credentials and a web UI that answers.
func TestSplunkLocalHintNeedsAWebUIThatAnswers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	answers := false
	orig := splunkWebAnswers
	splunkWebAnswers = func() bool { return answers }
	t.Cleanup(func() { splunkWebAnswers = orig })

	if out := captureStdout(t, printSplunkLocalHint); out != "" {
		t.Fatalf("hint with no local Splunk set up: %q", out)
	}
	env := filepath.Join(home, "splunk-bridge", "env", ".env")
	if err := os.MkdirAll(filepath.Dir(env), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env, []byte("SPLUNK_PASSWORD=test-only-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := captureStdout(t, printSplunkLocalHint); out != "" {
		t.Fatalf("hint for a web UI that does not answer: %q", out)
	}
	answers = true
	out := captureStdout(t, printSplunkLocalHint)
	if !strings.Contains(out, "Splunk Local Mode") || !strings.Contains(out, "http://127.0.0.1:8000") || !strings.Contains(out, env) ||
		strings.Contains(out, "test-only-value") {
		t.Fatalf("hint = %q", out)
	}
}
