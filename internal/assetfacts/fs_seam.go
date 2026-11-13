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

package assetfacts

import (
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
)

// The reads of this package go through the fixturefs seam, which is the
// identity in every product build (see package fixturefs).

func fsStat(name string) (os.FileInfo, error)  { return os.Stat(fixturefs.Map(name)) }
func fsLstat(name string) (os.FileInfo, error) { return os.Lstat(fixturefs.Map(name)) }
func fsOpen(name string) (*os.File, error)     { return os.Open(fixturefs.Map(name)) }

func fsReadlink(name string) (string, error) {
	target, err := os.Readlink(fixturefs.Map(name))
	return fixturefs.Unmap(target), err
}

func fsEvalSymlinks(name string) (string, error) {
	resolved, err := filepath.EvalSymlinks(fixturefs.Map(name))
	return fixturefs.Unmap(resolved), err
}
