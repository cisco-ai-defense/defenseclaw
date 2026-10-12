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

//go:build !linux

package plane

// NewTetragonSource is the native source outside Linux: Tetragon runs only
// on Linux, and the managed helpers of macOS and Windows ignore the
// enterprise.tetragon block.
func NewTetragonSource(homeDirs []string, _ TetragonOptions) Source { return NewSource(homeDirs) }
