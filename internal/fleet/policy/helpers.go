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

package policy

import (
	"os"
)

// File I/O helpers — thin wrappers so tests can verify compiler invocation
// without needing to mock the entire os package.

func makeTempDir() (string, error) {
	return os.MkdirTemp("", "dclaw-policy-*")
}

func removeAll(path string) error {
	return os.RemoveAll(path)
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
