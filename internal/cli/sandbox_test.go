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

package cli

import (
	"reflect"
	"testing"
)

func TestSandboxExecParsesHelpAndPreservesCommandFlags(t *testing.T) {
	if sandboxExecCmd.DisableFlagParsing {
		t.Fatal("sandbox exec must leave flag parsing enabled so --help is handled before persistent startup hooks")
	}

	sandboxExecCmd.InitDefaultHelpFlag()
	sandboxExecNetns = false
	if err := sandboxExecCmd.Flags().Set("netns", "false"); err != nil {
		t.Fatalf("reset --netns before test: %v", err)
	}
	if err := sandboxExecCmd.ParseFlags(nil); err != nil {
		t.Fatalf("reset args before test: %v", err)
	}
	t.Cleanup(func() {
		sandboxExecNetns = false
		_ = sandboxExecCmd.Flags().Set("netns", "false")
		_ = sandboxExecCmd.ParseFlags(nil)
	})

	if err := sandboxExecCmd.ParseFlags([]string{"--netns", "--", "printf", "--help"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if !sandboxExecNetns {
		t.Fatal("--netns was not parsed")
	}
	if got, want := sandboxExecCmd.Flags().Args(), []string{"printf", "--help"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("command args = %q, want %q", got, want)
	}
}
