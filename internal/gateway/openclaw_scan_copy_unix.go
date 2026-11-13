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

package gateway

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Bounds of the private scan copy: an OpenClaw skill or plugin folder is
// small; a larger tree is refused, not truncated.
const (
	openClawScanCopyMaxEntries = 20000
	openClawScanCopyMaxBytes   = 256 << 20
)

// copyOpenClawScanTarget copies target into a new private folder and returns
// it. The walk starts at the anchor that contains the resolved target and
// opens every level below it with O_NOFOLLOW, so a folder the OpenClaw account
// swaps for a link after the path check makes the copy fail instead of
// reading outside the account (rel-1-0-10 REVIEW-6 P2-1). Links inside the
// tree are not followed and not copied.
func copyOpenClawScanTarget(target string, anchors []string) (string, error) {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", err
	}
	anchor, rel := "", ""
	for _, a := range anchors {
		ra, err := filepath.EvalSymlinks(a)
		if err != nil {
			continue
		}
		if resolved == ra {
			anchor, rel = ra, "."
			break
		}
		if strings.HasPrefix(resolved, ra+string(filepath.Separator)) {
			anchor, rel = ra, strings.TrimPrefix(resolved, ra+string(filepath.Separator))
			break
		}
	}
	if anchor == "" {
		return "", fmt.Errorf("%s is outside the OpenClaw account", target)
	}
	fd, err := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	if rel != "." {
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			_ = unix.Close(fd)
			if err != nil {
				return "", fmt.Errorf("open %s without following links: %w", target, err)
			}
			fd = next
		}
	}
	dest, err := os.MkdirTemp("", "dc-openclaw-scan-")
	if err != nil {
		_ = unix.Close(fd)
		return "", err
	}
	budget := &openClawCopyBudget{entries: openClawScanCopyMaxEntries, bytes: openClawScanCopyMaxBytes}
	name := filepath.Join(dest, filepath.Base(resolved))
	if err := copyOpenClawFD(fd, name, budget); err != nil {
		_ = os.RemoveAll(dest)
		return "", err
	}
	return name, nil
}

type openClawCopyBudget struct{ entries, bytes int64 }

// copyOpenClawFD copies the open file or folder fd (closed here) to dest.
func copyOpenClawFD(fd int, dest string, budget *openClawCopyBudget) error {
	f := os.NewFile(uintptr(fd), dest)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	budget.entries--
	if budget.entries < 0 {
		return errOpenClawScanCopyTooLarge
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		budget.bytes -= st.Size
		if budget.bytes < 0 {
			return errOpenClawScanCopyTooLarge
		}
		out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, io.LimitReader(f, st.Size))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	case unix.S_IFDIR:
		if err := os.Mkdir(dest, 0o700); err != nil {
			return err
		}
		names, err := f.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, n := range names {
			child, err := unix.Openat(fd, n, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if err != nil {
				if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENXIO) || errors.Is(err, unix.EACCES) {
					continue // a link, a socket or an unreadable entry: not copied
				}
				return err
			}
			if err := copyOpenClawFD(child, filepath.Join(dest, n), budget); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil // devices, fifos, sockets: not copied
	}
}
