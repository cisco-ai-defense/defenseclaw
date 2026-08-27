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

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if commandName := releaseCommandNameForExecutable(); commandName != "" {
		cli.SetCommandName(commandName)
	}
	cli.SetVersion(version)
	cli.SetBuildInfo(commit, date)
	if handled, code := runWindowsService(func(ctx context.Context) int {
		return cli.ExecuteContext(ctx)
	}); handled {
		os.Exit(code)
	}
	os.Exit(cli.Execute())
}

func releaseCommandNameForExecutable() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	return releaseCommandNameForPath(executable)
}

func releaseCommandNameForPath(executable string) string {
	base := filepath.Base(executable)
	extension := filepath.Ext(base)
	base = strings.TrimSuffix(base, extension)
	if strings.EqualFold(base, "defenseclaw") {
		return "defenseclaw"
	}
	return ""
}
