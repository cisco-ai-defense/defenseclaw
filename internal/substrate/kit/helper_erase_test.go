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

//go:build linux

package kit

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runHelper runs the actor's git credential helper with sh, the way git
// in the actor does.
func runHelper(t *testing.T, op, input string) (stdout, stderr string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "git-credential-defenseclaw")
	if err := os.WriteFile(p, []byte(gitCredentialHelper), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", p, op)
	cmd.Stdin = strings.NewReader(input)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper %s: %v %s", op, err, errb.String())
	}
	return out.String(), errb.String()
}

func TestB1HelperEraseHint(t *testing.T) {
	out, errOut := runHelper(t, "get", "protocol=https\nhost=git.corp.example\n\n")
	if out != "username=x-access-token\npassword=placeholder-not-a-secret\n" || errOut != "" {
		t.Fatalf("get: %q %q", out, errOut)
	}
	out, errOut = runHelper(t, "erase", "protocol=https\nhost=gitlab.com\nusername=x-access-token\npassword=placeholder-not-a-secret\n\n")
	want := "DefenseClaw: gitlab.com refused the request. On your computer run: defenseclaw substrate secrets add NAME --template gitlab --host gitlab.com\n"
	if out != "" || errOut != want {
		t.Fatalf("erase: %q %q", out, errOut)
	}
	// A host the built-ins do not know: the templates command; the port
	// and anything but letters, digits, dots and dashes are cut, so the
	// remote cannot write terminal controls or a command of its own.
	_, errOut = runHelper(t, "erase", "protocol=https\nhost=git.corp\x1b[2J.example;rm -rf ~:8443\n\n")
	if !strings.Contains(errOut, "DefenseClaw: git.corp2J.examplerm-rf refused the request.") ||
		!strings.Contains(errOut, "--template TEMPLATE --host git.corp2J.examplerm-rf\n") ||
		!strings.Contains(errOut, "secrets templates lists the templates") || strings.ContainsAny(errOut, "\x1b;~") {
		t.Fatalf("sanitized erase: %q", errOut)
	}
	for _, op := range []string{"store", ""} {
		if out, errOut = runHelper(t, op, "protocol=https\nhost=gitlab.com\n\n"); out != "" || errOut != "" {
			t.Fatalf("%q: %q %q", op, out, errOut)
		}
	}
	if _, errOut = runHelper(t, "erase", "protocol=https\n\n"); errOut != "" {
		t.Fatalf("no host: %q", errOut)
	}
}
