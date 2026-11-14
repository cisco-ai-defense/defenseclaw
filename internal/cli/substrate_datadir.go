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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
)

var substrateDataDirFlags struct {
	path     string
	uid, gid int
	mode     string
	policies string
}

// substrateDataDirCmd is the chart's init container step in managed mode
// (GAP-0135): a volume's root is 0777 and root-owned, which the managed
// data_dir trust check refuses, and the distroless image has no shell, so
// the gateway binary itself gives the volume root to the gateway account.
var substrateDataDirCmd = &cobra.Command{
	Use:         "substrate-datadir",
	Short:       "Give a data volume to the gateway account (chart init container, managed mode)",
	Hidden:      true,
	Args:        cobra.NoArgs,
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	RunE: func(cmd *cobra.Command, _ []string) error {
		f := substrateDataDirFlags
		mode, err := strconv.ParseUint(f.mode, 8, 32)
		if err != nil || mode&0o077 != 0 || mode&0o700 != 0o700 {
			return fmt.Errorf("substrate-datadir: --mode %q must be 0700 (owner only)", f.mode)
		}
		if err := prepareSubstrateDataDir(f.path, f.uid, f.gid, os.FileMode(mode)); err != nil {
			return err
		}
		if f.policies != "" {
			return seedRootPolicies(f.policies)
		}
		return nil
	},
}

func init() {
	f := substrateDataDirCmd.Flags()
	f.StringVar(&substrateDataDirFlags.path, "path", "", "the volume root (absolute)")
	f.IntVar(&substrateDataDirFlags.uid, "uid", 65532, "owner UID (the gateway account)")
	f.IntVar(&substrateDataDirFlags.gid, "gid", 65532, "owner GID")
	f.StringVar(&substrateDataDirFlags.mode, "mode", "0700", "mode (owner only)")
	f.StringVar(&substrateDataDirFlags.policies, "policies", "", "also write the embedded policies into this volume root, root-owned and read-only (managed policy_dir)")
	rootCmd.AddCommand(substrateDataDirCmd)
}

func prepareSubstrateDataDir(path string, uid, gid int, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return fmt.Errorf("substrate-datadir: --path %q must be a clean absolute path below /", path)
	}
	if uid <= 0 || gid < 0 {
		return errors.New("substrate-datadir: --uid must be the non-root gateway account")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("substrate-datadir: %w (it must be the mounted volume)", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("substrate-datadir: %s is not a directory", path)
	}
	if err := os.Lchown(path, uid, gid); err != nil {
		return fmt.Errorf("substrate-datadir: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("substrate-datadir: %w", err)
	}
	fmt.Printf("substrate-datadir: %s owned by %d:%d mode %04o\n", path, uid, gid, mode)
	return nil
}

// seedRootPolicies writes the embedded policies into a volume root as the
// managed policy_dir: root-owned, folders 0755, files 0444, so the gateway
// account reads them and cannot change them (the managed trust check).
func seedRootPolicies(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
		return fmt.Errorf("substrate-datadir: --policies %q must be a clean absolute path below /", dir)
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("substrate-datadir: --policies %s must be the mounted volume", dir)
	}
	if err := writeSubstratePolicies(dir, 0o755, 0o444); err != nil {
		return err
	}
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if err := os.Lchown(p, 0, 0); err != nil {
			return err
		}
		mode := os.FileMode(0o444)
		if d.IsDir() {
			mode = 0o755
		}
		return os.Chmod(p, mode)
	})
	if err != nil {
		return fmt.Errorf("substrate-datadir: policies: %w", err)
	}
	fmt.Printf("substrate-datadir: policies written to %s (root-owned, read-only)\n", dir)
	return nil
}
