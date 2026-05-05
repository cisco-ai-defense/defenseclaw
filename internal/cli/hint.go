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
	"fmt"
	"os"

	"golang.org/x/term"
)

// printHint prints dim post-command hints when stdout is an interactive
// terminal or when color forcing is enabled (CI logs with FORCE_COLOR).
func printHint(lines ...string) {
	fd := int(os.Stdout.Fd())
	if !term.IsTerminal(fd) && !ColorEnabled() {
		return
	}
	fmt.Println()
	for _, line := range lines {
		fmt.Println(Dim(line))
	}
}
