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
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
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
