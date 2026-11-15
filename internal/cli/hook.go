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
	"os"

	"github.com/defenseclaw/defenseclaw/internal/hookcli"
)

func init() {
	rootCmd.AddCommand(hookcli.NewHookCmd())
}

// hookConfigMaxBytes bounds the config.yaml read of readHookConfigDocument.
const hookConfigMaxBytes = 4 << 20

// readHookConfigDocument returns the config.yaml document at path, or nil
// when it is missing, not a regular file or larger than hookConfigMaxBytes.
func readHookConfigDocument(path string) []byte {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > hookConfigMaxBytes {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}
