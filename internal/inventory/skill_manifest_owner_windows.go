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

package inventory

import (
	"io/fs"
	"os"
)

// skillManifestOwned keeps every SKILL.md on Windows: a hard link there
// needs write access to its target, so a user cannot link in a file they
// cannot read.
func skillManifestOwned(*os.File, fs.FileInfo) bool { return true }

// skillHardLinked is false on Windows: a hard link there needs write access
// to its target, so a user cannot link in a file they cannot reach.
func skillHardLinked(*os.File) bool { return false }
