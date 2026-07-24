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

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// otlpValidateDirectory is a no-op on Unix, where the existing token-file
// mode and ownership checks remain the compatibility contract.
func otlpValidateDirectory(_ string) error {
	return nil
}

// otlpOpenNoFollow returns O_NOFOLLOW flag value for symlink-safe file opens.
func otlpOpenNoFollow() int {
	return syscall.O_NOFOLLOW
}

// otlpValidatePerm enforces that the token file is not group/other accessible.
// On Unix the file is created 0600, so anything else is a tampering signal.
func otlpValidatePerm(path string, info os.FileInfo) error {
	if mode := info.Mode().Perm(); mode != 0o600 {
		return fmt.Errorf("OTLP path-token %s has mode %o, want 600", path, mode)
	}
	return nil
}

// otlpValidateOwner checks that the file at the given path is owned by the
// effective user performing the filesystem operation. Enterprise hook
// guardians keep a real uid of 0 while temporarily dropping their effective
// uid to the target user, so comparing against the real uid would reject files
// that the target user just created.
func otlpValidateOwner(path string, info os.FileInfo) error {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != os.Geteuid() && !hookAPITrustedOwner(stat.Uid) {
			return fmt.Errorf("OTLP path-token %s uid %d is not root, effective uid %d, real uid %d, or the defenseclaw service uid", path, stat.Uid, os.Geteuid(), os.Getuid())
		}
	}
	return nil
}

func otlpValidateRemovalOwner(path string, info os.FileInfo) error {
	return otlpValidateOwner(path, info)
}

func otlpValidateTokenDirectory(_, _ string) error {
	return nil
}

func otlpPathTokenNeedsSecureReplacement(_ string) (bool, error) {
	return false, nil
}

func createSecureOTLPPathTokenTempFile(tokenPath string) (*os.File, string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(tokenPath), otlpPathTokenTempPrefix(tokenPath)+"*")
	if err != nil {
		return nil, "", err
	}
	if err := tmp.Chmod(0o600); err != nil {
		path := tmp.Name()
		_ = tmp.Close()
		_ = os.Remove(path)
		return nil, "", err
	}
	return tmp, tmp.Name(), nil
}
