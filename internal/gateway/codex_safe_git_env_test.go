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
	"strconv"
	"strings"
	"testing"
)

// TestF3347_SafeGitEnv_OverridesRepoLocalConfig verifies safeGitEnv()
// emits a self-consistent GIT_CONFIG_COUNT/KEY_<n>/VALUE_<n> trio.
// Avarice F-3347: without this trio git's repo-local config is the
// only override layer, so a hostile workspace could re-enable
// core.fsmonitor / core.hooksPath even after we set
// GIT_CONFIG_NOSYSTEM=1.
func TestF3347_SafeGitEnv_OverridesRepoLocalConfig(t *testing.T) {
	env := safeGitEnv()

	want := map[string]string{
		"GIT_CONFIG_NOSYSTEM":   "1",
		"GIT_CONFIG_GLOBAL":     "/dev/null",
		"GIT_CONFIG_PARAMETERS": "",
	}
	for k, v := range want {
		if !envContains(env, k+"="+v) {
			t.Fatalf("safeGitEnv() missing %s=%s", k, v)
		}
	}

	// Recover GIT_CONFIG_COUNT and verify each (KEY_<n>, VALUE_<n>)
	// pair is present.
	countStr := envGet(env, "GIT_CONFIG_COUNT")
	if countStr == "" {
		t.Fatalf("safeGitEnv() did not set GIT_CONFIG_COUNT")
	}
	count, err := strconv.Atoi(countStr)
	if err != nil || count <= 0 {
		t.Fatalf("invalid GIT_CONFIG_COUNT=%q", countStr)
	}
	for i := 0; i < count; i++ {
		keyName := "GIT_CONFIG_KEY_" + strconv.Itoa(i)
		valName := "GIT_CONFIG_VALUE_" + strconv.Itoa(i)
		if envGet(env, keyName) == "" {
			t.Fatalf("missing %s", keyName)
		}
		// VALUE may legitimately be the empty string but the key
		// itself must exist; we look it up without requiring a
		// non-empty result.
		if !envHasName(env, valName) {
			t.Fatalf("missing %s", valName)
		}
	}

	// Critical overrides that must appear among the KEY_<n> values.
	required := []string{
		"core.fsmonitor",
		"core.hooksPath",
		"core.sshCommand",
		"core.gitProxy",
		"protocol.allow",
	}
	for _, want := range required {
		if !envHasValueAmongKeys(env, count, want) {
			t.Fatalf("safeGitEnv() does not override %s", want)
		}
	}
}

func envContains(env []string, prefix string) bool {
	for _, e := range env {
		if e == prefix || strings.HasPrefix(e, prefix+"=") || e == prefix {
			return true
		}
	}
	return false
}

func envGet(env []string, name string) string {
	for _, e := range env {
		if strings.HasPrefix(e, name+"=") {
			return e[len(name)+1:]
		}
	}
	return ""
}

func envHasName(env []string, name string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, name+"=") {
			return true
		}
	}
	return false
}

func envHasValueAmongKeys(env []string, count int, want string) bool {
	for i := 0; i < count; i++ {
		if envGet(env, "GIT_CONFIG_KEY_"+strconv.Itoa(i)) == want {
			return true
		}
	}
	return false
}
