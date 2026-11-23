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
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

const sourceTestValue = "tok9Qv7Zr2Lw5Xn8"

// fakeSourceTool puts a fake tool named bin in dir. It records its
// arguments, one per line, in dir/bin.args and prints out on standard
// output and errText on standard error, then exits with code.
func fakeSourceTool(t *testing.T, dir, bin, out, errText string, code int) {
	t.Helper()
	args := filepath.Join(dir, bin+".args")
	var body, name string
	if runtime.GOOS == "windows" {
		name = bin + ".cmd"
		body = "@echo off\r\n(for %%a in (%*) do @echo %%~a) > \"" + args + "\"\r\n"
		if out != "" {
			body += "echo " + out + "\r\n"
		}
		if errText != "" {
			body += "echo " + errText + " 1>&2\r\n"
		}
		body += "exit /b " + itoa(code) + "\r\n"
	} else {
		name = bin
		body = "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '" + args + "'\n"
		if out != "" {
			body += "printf '%s\\n' '" + out + "'\n"
		}
		if errText != "" {
			body += "printf '%s\\n' '" + errText + "' >&2\n"
		}
		body += "exit " + itoa(code) + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func readArgs(t *testing.T, dir, bin string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, bin+".args"))
	if err != nil {
		t.Fatalf("the fake %s did not run: %v", bin, err)
	}
	return strings.Fields(string(b))
}

// sourceAdmin is a fake gateway that keeps the stored value.
func sourceAdmin(t *testing.T) *map[string]string {
	t.Helper()
	stored := map[string]string{}
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"PUT secrets/TOK": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&stored)
			w.WriteHeader(http.StatusNoContent)
		},
	}})
	return &stored
}

// onlyPath makes dir the whole PATH, so a real gh, op or security on the
// build host cannot answer.
func onlyPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
	}
	return dir
}

func TestB1SourcesNoArgvNoEcho(t *testing.T) {
	cases := []struct {
		name     string
		bin      string
		args     []string
		wantArgv []string
	}{
		{"gh", "gh", []string{"--from-gh"}, []string{"auth", "token"}},
		{"gh host", "gh", []string{"--from-gh", "--gh-host", "ghe.example.test"}, []string{"auth", "token", "--hostname", "ghe.example.test"}},
		{"op", "op", []string{"--from-op", "op://eng/gitlab/token"}, []string{"read", "--no-newline", "op://eng/gitlab/token"}},
		{"keychain", "security", []string{"--from-keychain", "npm-publish", "--account", "dev"}, []string{"find-generic-password", "-s", "npm-publish", "-a", "dev", "-w"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := onlyPath(t)
			fakeSourceTool(t, dir, tc.bin, sourceTestValue, "", 0)
			old := substrateSourceGOOS
			substrateSourceGOOS = "darwin"
			t.Cleanup(func() { substrateSourceGOOS = old })
			stored := sourceAdmin(t)
			out, errOut, err := runSubstrate(t, newSubstrateSecretsSetCmd(), append([]string{"TOK"}, tc.args...)...)
			if err != nil || (*stored)["value"] != sourceTestValue {
				t.Fatalf("set = %v (stored %q), out %q err %q", err, (*stored)["value"], out, errOut)
			}
			argv := readArgs(t, dir, tc.bin)
			if strings.Join(argv, " ") != strings.Join(tc.wantArgv, " ") {
				t.Errorf("%s argv = %q, want %q", tc.bin, argv, tc.wantArgv)
			}
			for _, a := range argv {
				if strings.Contains(a, sourceTestValue) {
					t.Errorf("the value is in the tool's argv: %q", argv)
				}
			}
			if strings.Contains(out+errOut, sourceTestValue) {
				t.Errorf("the value was printed: %q %q", out, errOut)
			}
		})
	}
}

func TestB1SourceFromFile(t *testing.T) {
	stored := sourceAdmin(t)
	file := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(file, []byte(sourceTestValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, err := runSubstrate(t, newSubstrateSecretsSetCmd(), "TOK", "--from-file", file)
	if err != nil || (*stored)["value"] != sourceTestValue {
		t.Fatalf("set --from-file = %v (stored %q)", err, (*stored)["value"])
	}
	if strings.Contains(out+errOut, sourceTestValue) {
		t.Errorf("the value was printed: %q %q", out, errOut)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	big := filepath.Join(t.TempDir(), "big")
	_ = os.WriteFile(big, []byte(strings.Repeat("a", substrateSecretMaxBytes+1)), 0o600)
	for name, p := range map[string]string{"missing": filepath.Join(t.TempDir(), "nope"), "empty": empty, "too big": big, "a directory": t.TempDir()} {
		if _, _, err := runSubstrate(t, newSubstrateSecretsSetCmd(), "TOK", "--from-file", p); err == nil {
			t.Errorf("%s file: want a refusal", name)
		}
	}
}

func TestB1SourceToolMissingSaysReasonAndFix(t *testing.T) {
	cases := []struct {
		args []string
		fix  string
	}{
		{[]string{"--from-gh"}, "gh auth login"},
		{[]string{"--from-op", "op://eng/gitlab/token"}, "op signin"},
		{[]string{"--from-keychain", "npm-publish"}, "/usr/bin/security"},
	}
	for _, tc := range cases {
		onlyPath(t)
		old := substrateSourceGOOS
		substrateSourceGOOS = "darwin"
		_, _, err := runSubstrate(t, newSubstrateSecretsSetCmd(), append([]string{"TOK"}, tc.args...)...)
		substrateSourceGOOS = old
		if err == nil || !strings.Contains(err.Error(), "(secret_source_tool_missing)") || !strings.Contains(err.Error(), tc.fix) {
			t.Errorf("%v: err = %v, want secret_source_tool_missing and %q", tc.args, err, tc.fix)
		}
	}
}

func TestB1SourceKeychainOnlyOnMac(t *testing.T) {
	dir := onlyPath(t)
	fakeSourceTool(t, dir, "security", sourceTestValue, "", 0)
	old := substrateSourceGOOS
	substrateSourceGOOS = "linux"
	t.Cleanup(func() { substrateSourceGOOS = old })
	_, _, err := runSubstrate(t, newSubstrateSecretsSetCmd(), "TOK", "--from-keychain", "npm-publish")
	if err == nil || !strings.Contains(err.Error(), "(secret_source_unsupported)") {
		t.Fatalf("err = %v, want secret_source_unsupported", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "security.args")); err == nil {
		t.Error("the keychain tool ran on a computer that is not a Mac")
	}
}

func TestB1SourceToolFailureIsCleanAndHidesTheValue(t *testing.T) {
	dir := onlyPath(t)
	// A tool that fails after printing the value on both streams.
	fakeSourceTool(t, dir, "gh", sourceTestValue, "error for "+sourceTestValue+" not logged in", 1)
	sourceAdmin(t)
	_, _, err := runSubstrate(t, newSubstrateSecretsSetCmd(), "TOK", "--from-gh")
	if err == nil || !strings.Contains(err.Error(), "(secret_source_failed)") {
		t.Fatalf("err = %v, want secret_source_failed", err)
	}
	if strings.Contains(err.Error(), sourceTestValue) || !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("err = %q: want the tool's reason without the value", err)
	}
	// A tool that succeeds but prints nothing.
	fakeSourceTool(t, dir, "gh", "", "", 0)
	if _, _, err := runSubstrate(t, newSubstrateSecretsSetCmd(), "TOK", "--from-gh"); err == nil || !strings.Contains(err.Error(), "(secret_source_failed)") {
		t.Fatalf("empty answer: err = %v", err)
	}
}

func TestB1SourceUseOneSource(t *testing.T) {
	sourceAdmin(t)
	t.Setenv("SUBSTRATE_TEST_SECRET", sourceTestValue)
	for _, args := range [][]string{
		{"--from-gh", "--stdin"},
		{"--from-env", "SUBSTRATE_TEST_SECRET", "--from-file", "x"},
		{"--gh-host", "ghe.example.test", "--stdin"},
		{"--account", "dev", "--stdin"},
		{"--from-op", "1password-item"},
		{"--from-gh", "--gh-host=-evil"},
	} {
		_, _, err := runSubstrate(t, newSubstrateSecretsSetCmd(), append([]string{"TOK"}, args...)...)
		if err == nil || cliusage.ExitCode(err) != 2 {
			t.Errorf("%v: err = %v (exit %d), want a usage error with exit 2", args, err, cliusage.ExitCode(err))
		}
	}
}

func TestB1DoctorRowsForSourceTools(t *testing.T) {
	dir := onlyPath(t)
	fakeSourceTool(t, dir, "gh", "", "", 0)
	old := substrateSourceGOOS
	substrateSourceGOOS = "linux"
	t.Cleanup(func() { substrateSourceGOOS = old })
	d := &doctorRun{}
	doctorSecretSources(d)
	got := map[string]substrateCheck{}
	for _, c := range d.checks {
		got[c.ID] = c
	}
	if got["source_gh"].Status != doctorOK {
		t.Errorf("source_gh = %+v, want ok", got["source_gh"])
	}
	if c := got["source_op"]; c.Status != doctorSkip || !strings.Contains(c.Summary, "op signin") {
		t.Errorf("source_op = %+v, want skip with the install hint", c)
	}
	if c := got["source_security"]; c.Status != doctorSkip || !strings.Contains(c.Summary, "only on macOS") {
		t.Errorf("source_security = %+v, want skip (not a Mac)", c)
	}
	for _, c := range d.checks {
		if c.Status == doctorFail {
			t.Errorf("an optional tool must never fail the doctor: %+v", c)
		}
	}
}
