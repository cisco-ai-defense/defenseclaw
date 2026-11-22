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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// Managed enterprise on Agent Substrate (GAP-0135, lead ruling 11-12
// 23:55Z): the gateway runs in a pod the chart starts, with no laptop
// lifecycle and no laptop activation record. The activated config is the
// one the chart mounts: config.yaml by subPath, a regular file owned by
// root that nobody may write, in a root-owned directory no other account
// may write, whose bytes are the bytes the gateway booted from. A
// symlinked ConfigMap mount (..data), a writable file, or a file owned by
// the gateway's own account is not that layout and is refused as before.
//
// The check exists only when `serve --substrate` registers it in a cluster
// (SetSubstrateClusterActivation); a host never has it, so the laptop
// lifecycle and the signed-bundle rules stay exactly as they are.

// substrateClusterActivation is the registered check (nil on every host).
var substrateClusterActivation atomic.Pointer[func(path string, raw []byte) error]

// SetSubstrateClusterActivation registers the cluster activation check of
// a managed Substrate gateway; nil removes it.
func SetSubstrateClusterActivation(fn func(path string, raw []byte) error) {
	if fn == nil {
		substrateClusterActivation.Store(nil)
		return
	}
	substrateClusterActivation.Store(&fn)
}

// SubstrateActivationSources is the one registered check over its sources
// in order (the chart-mounted file, then a verified Substrate bundle): the
// first that accepts the start activates it; when none does, the refusal
// names every source's reason.
func SubstrateActivationSources(sources ...func(path string, raw []byte) error) func(path string, raw []byte) error {
	return func(path string, raw []byte) error {
		errs := make([]error, 0, len(sources))
		for _, src := range sources {
			err := src(path, raw)
			if err == nil {
				return nil
			}
			errs = append(errs, err)
		}
		if len(errs) == 0 {
			return errors.New("substrate activation: no source")
		}
		return errors.Join(errs...)
	}
}

// SubstrateMountedConfigActivation is the chart-mounted layout check.
// owner returns a file's owner uid (the stat owner; tests replace it).
func SubstrateMountedConfigActivation(owner func(os.FileInfo) (uint32, bool)) func(path string, raw []byte) error {
	return func(path string, raw []byte) error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("substrate activation: config.yaml is not a regular file (a ConfigMap mount must use subPath)")
		}
		if info.Mode().Perm()&0o222 != 0 {
			return fmt.Errorf("substrate activation: config.yaml mode %04o is writable", info.Mode().Perm())
		}
		if uid, ok := owner(info); !ok || uid != 0 {
			return errors.New("substrate activation: config.yaml is not owned by root")
		}
		dir, err := os.Lstat(filepath.Dir(path))
		if err != nil {
			return err
		}
		if !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 || dir.Mode().Perm()&0o022 != 0 {
			return errors.New("substrate activation: the config directory is a link or writable by others")
		}
		if uid, ok := owner(dir); !ok || uid != 0 {
			return errors.New("substrate activation: the config directory is not owned by root")
		}
		disk, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(disk, raw) {
			return errors.New("substrate activation: the boot bytes are not the mounted config")
		}
		return nil
	}
}
