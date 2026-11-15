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

//go:build s7bench

package fixturefs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// mutableRoots are the trees other processes write to while a benchmark runs.
// Everything else a decision reads (/etc, the fixture home, the policy files)
// is the same on every box.
var mutableRoots = []string{"/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/private/var/tmp"}

var root string

func init() {
	r := os.Getenv("S7_FIXTURE_FS_ROOT")
	if r == "" {
		fmt.Fprintln(os.Stderr, "[s7bench] fixture fs: LIVE (S7_FIXTURE_FS_ROOT is not set; globs and path checks read the real /tmp)")
		return
	}
	abs, err := filepath.Abs(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[s7bench] fixture fs: FATAL bad S7_FIXTURE_FS_ROOT:", err)
		os.Exit(2)
	}
	root = abs
	for _, m := range mutableRoots {
		d := filepath.Join(root, m)
		if err := os.MkdirAll(d, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "[s7bench] fixture fs: FATAL", err)
			os.Exit(2)
		}
		_ = os.Chmod(d, os.ModeSticky|0o777) // as the live /tmp
	}
	fmt.Fprintln(os.Stderr, "[s7bench] fixture fs: hermetic, mutable system roots read from the fixture tree")
}

// Map sends a path under a mutable system root to the fixture tree.
func Map(name string) string {
	if root == "" {
		return name
	}
	for _, m := range mutableRoots {
		if name == m || strings.HasPrefix(name, m+"/") {
			return root + name
		}
	}
	return name
}

// Unmap undoes Map for a path a read returned (a link target, a resolved path).
func Unmap(name string) string {
	if root != "" && strings.HasPrefix(name, root+"/") {
		return name[len(root):]
	}
	return name
}
