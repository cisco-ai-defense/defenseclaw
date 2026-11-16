// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// The generated registration must keep a real proof path usable after the
// macOS launcher makes descendant creation impossible. Check all render
// modes because the same script template serves per-user and managed hosts.
func TestHermesGeneratedDarwinForklessProof(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("RLIMIT_NPROC does not confine root")
	}
	for _, mode := range []struct {
		name string
		opts SetupOpts
	}{
		{"per-user", SetupOpts{HookFailMode: "closed"}},
		{"standalone", SetupOpts{ManagedEnterprise: true, ManagedHookSocket: "/var/run/defenseclaw/hook.sock", HookFailMode: "closed"}},
		{"secure-client", SetupOpts{ManagedEnterprise: true, SecureClientHookDelivery: true, HookFailMode: "closed"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			opts := mode.opts
			opts.DataDir = t.TempDir()
			opts.APIAddr = "127.0.0.1:18970"
			opts.APIToken = "probe-test-token"
			hookDir := filepath.Join(opts.DataDir, "hooks")
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewHermesConnector()); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(hookDir, "hermes-hook.sh")
			if !runHermesExecutionProbe(script, []string{"--defenseclaw-execution-probe", "--forkless"}) {
				t.Fatal("generated Hermes hook has no bounded forkless execution proof")
			}
			if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), []byte("exit 7\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if runHermesExecutionProbe(script, []string{"--defenseclaw-execution-probe", "--forkless"}) {
				t.Fatal("forkless proof passed with a broken hardening helper")
			}
		})
	}
}

func TestHermesDarwinRegistrationUsesForklessProof(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("RLIMIT_NPROC does not confine root")
	}
	script := filepath.Join(t.TempDir(), "hermes-hook.sh")
	const body = "#!/bin/sh\n[ \"$1\" = --defenseclaw-execution-probe ] && [ \"$2\" = --forkless ] || exit 7\nprintf 'defenseclaw-execution-probe-ok\\n'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	if !hermesRegisteredCommandExecutable(SetupOpts{}, script) {
		t.Fatal("Darwin Verify did not pass the bounded forkless argument")
	}
}
