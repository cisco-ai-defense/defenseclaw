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

// defenseclaw-hook is the native Windows hook/notification entrypoint. Release
// builds link it with -H=windowsgui so graphical agent applications can invoke
// DefenseClaw synchronously without Windows allocating a transient console.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Identity inspection must not depend on mutable per-user hook state. Setup
	// invokes this exact mode before signing and after installation so archived
	// hook bytes are bound to the payload manifest's source commit.
	if isIdentityEntrypoint(os.Args[1:]) {
		if err := writeMachineIdentity(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "defenseclaw-hook: write identity: %v\n", err)
			os.Exit(1)
		}
		return
	}
	// The stable Windows launcher survives uninstall because agent clients may
	// cache its absolute command for the lifetime of their process. Disabled,
	// publishing, missing, or unsafe installer state is an intentional no-op;
	// check it before parsing project-inherited environment or fail-mode flags.
	if cli.NativeHookRuntimeNoop() {
		os.Exit(0)
	}
	if !isHookEntrypoint(os.Args[1:]) {
		fmt.Fprintln(os.Stderr, "defenseclaw-hook: expected hook or notify subcommand")
		os.Exit(2)
	}
	cli.SetVersion(version)
	cli.SetBuildInfo(commit, date)
	os.Exit(cli.Execute())
}

func isHookEntrypoint(args []string) bool {
	return len(args) > 0 && (args[0] == "hook" || args[0] == "notify")
}

func isIdentityEntrypoint(args []string) bool {
	return len(args) == 1 && args[0] == "--version-json"
}

func writeMachineIdentity(w io.Writer) error {
	return json.NewEncoder(w).Encode(struct {
		SchemaVersion int    `json:"schema_version"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		Commit        string `json:"commit"`
		Built         string `json:"built,omitempty"`
	}{
		SchemaVersion: 1,
		Name:          "defenseclaw-hook",
		Version:       version,
		Commit:        commit,
		Built:         date,
	})
}
