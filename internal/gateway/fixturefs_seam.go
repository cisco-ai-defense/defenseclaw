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

package gateway

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The reads of the agent hook config guard name paths a hook call names (a
// write target, a pathspec, a git -C folder), so each goes through the
// share-gated hookpaths readers, which read through the fixturefs seam: a
// share on another machine is never contacted and the path is judged by its
// text (rel-1-0-10:GAP-1074), and a local share that does not answer costs
// at most the share wait (rel-1-0-6:GAP-0482).

func seamStat(name string) (os.FileInfo, error)    { return hookpaths.Stat(name) }
func seamLstat(name string) (os.FileInfo, error)   { return hookpaths.Lstat(name) }
func seamOpen(name string) (*os.File, error)       { return hookpaths.Open(name) }
func seamReadFile(name string) ([]byte, error)     { return hookpaths.ReadFile(name) }
func seamReadlink(name string) (string, error)     { return hookpaths.Readlink(name) }
func seamEvalSymlinks(name string) (string, error) { return hookpaths.EvalSymlinks(name) }
