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

package openshell

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The administrator's OpenShell on a managed host (enterprise.openshell.install:
// prerequisite). The administrator installs NVIDIA's packages machine-wide
// (the rpm or deb on Linux; on macOS the binaries copied to /usr/local/bin,
// since a Homebrew prefix belongs to the person who ran brew), and an
// account's managed gateway unit runs that copy with the rendered
// configuration. The account never supplies the binary in this mode.

// AdminBinaryDirs are the folders the administrator's OpenShell binaries
// are looked up in, in order.
func AdminBinaryDirs(goos string) []string {
	if goos == "darwin" {
		return []string{"/usr/local/bin", "/opt/homebrew/bin"}
	}
	return []string{"/usr/bin", "/usr/local/bin"}
}

// ErrNoAdminBinary means the administrator's copy of a binary is not there,
// or is not one a standard account cannot have changed.
var ErrNoAdminBinary = errors.New("openshell: the administrator's OpenShell binary is not installed or not trusted")

// AdminBinary returns the administrator's copy of the OpenShell binary name
// (GatewayBinary, DefaultBinary): the first of AdminBinaryDirs that holds an
// executable regular file passing trusted (the managed trust check: owned by
// root, closed to other writers, no links on the way). Every candidate that
// exists but fails the check is named in the error, so the administrator
// sees what to fix.
func AdminBinary(goos, name string, trusted func(path string) error) (string, error) {
	var refused []string
	for _, dir := range AdminBinaryDirs(goos) {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		if trusted != nil {
			if err := trusted(path); err != nil {
				refused = append(refused, fmt.Sprintf("%s (%v)", path, err))
				continue
			}
		}
		return path, nil
	}
	if len(refused) > 0 {
		return "", fmt.Errorf("%w: %s", ErrNoAdminBinary, strings.Join(refused, "; "))
	}
	return "", fmt.Errorf("%w: %s is in none of %s", ErrNoAdminBinary, name, strings.Join(AdminBinaryDirs(goos), ", "))
}
