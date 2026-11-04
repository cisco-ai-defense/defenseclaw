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

//go:build unix

package config

import (
	"os"
	"syscall"
)

// DefaultEnvConfigPath is the AVC drop location on Unix managed installs.
// See the doc comment on the package-level declaration in env_config.go.
const DefaultEnvConfigPath = "/opt/cisco/secureclient/defenseclaw/env_config.json"

// ResolveDefaultEnvConfigPath returns the fixed AVC-owned Unix drop location.
func ResolveDefaultEnvConfigPath() (string, error) {
	return DefaultEnvConfigPath, nil
}

// openEnvConfig opens path with O_NOFOLLOW so a symlinked env_config
// (attacker replacement between stat and read on Unix) is rejected up
// front. The returned *os.File is used both for Fstat trust checks
// and for reading the JSON, so metadata and content come from the
// same inode.
func openEnvConfig(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return f, nil
}
