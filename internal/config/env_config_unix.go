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
	"errors"
	"fmt"
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

// trustEnvConfigFilePlatform enforces the uid==0 + not-group/world-writable
// check on Unix. When the process is not running as root (dev boxes,
// unit tests, opensource local runs) the invariant can't hold, so we
// skip the check and rely on the caller to only wire
// LoadEnvConfigEndpoint on managed_enterprise where the sidecar runs
// as uid 0.
func trustEnvConfigFilePlatform(info os.FileInfo) error {
	if os.Geteuid() != 0 {
		return nil
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("file metadata not verifiable on this platform")
	}
	if sys.Uid != 0 {
		return fmt.Errorf("must be owned by root (uid %d)", sys.Uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("must not be group- or world-writable (mode %o)", info.Mode().Perm())
	}
	return nil
}
