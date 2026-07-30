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

//go:build windows

package config

import "os"

// trustEnvConfigFilePlatform is a no-op on Windows. The managed deploy
// target for this env_config trust check is macOS + Linux; the shell
// installer's equivalent (_assert_trusted_env_config_file_or_die) is
// only invoked from packaging/macos/install.sh. Path-level trust on
// Windows is enforced elsewhere.
func trustEnvConfigFilePlatform(_ os.FileInfo) error {
	return nil
}

// openEnvConfig on Windows just does a plain read-only open; there is
// no O_NOFOLLOW-equivalent path-level flag exposed via os.OpenFile
// here, and the Windows managed deploy path does not source
// env_config.json (see trustEnvConfigFilePlatform doc). The file
// descriptor is still returned so LoadEnvConfigEndpoint stays
// TOCTOU-consistent between stat and read from the same handle.
func openEnvConfig(path string) (*os.File, error) {
	return os.Open(path)
}
