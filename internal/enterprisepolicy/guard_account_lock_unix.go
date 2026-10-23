// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockForeignHookRemovalFile takes a shared or exclusive flock within ctx,
// trying again every poll.
func lockForeignHookRemovalFile(ctx context.Context, file *os.File, exclusive bool, poll time.Duration) error {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	for {
		err := syscall.Flock(int(file.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func unlockForeignHookRemovalFile(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}

// openForeignHookLockFile opens or creates a lock file, never through a
// link.
func openForeignHookLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
}

// foreignHookLockFileOwner gives a lock file the owner of the folder it is
// in (the gateway service): root creates it when a removal comes first.
func foreignHookLockFileOwner(file *os.File, dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	folder, ok := info.Sys().(*syscall.Stat_t)
	opened, statErr := file.Stat()
	if statErr != nil {
		return statErr
	}
	own, ok2 := opened.Sys().(*syscall.Stat_t)
	if !ok || !ok2 {
		return errors.New("cannot read the owner")
	}
	if own.Uid == folder.Uid && own.Gid == folder.Gid {
		return nil
	}
	if err := file.Chown(int(folder.Uid), int(folder.Gid)); err != nil {
		return fmt.Errorf("give it the owner of %s: %w", dir, err)
	}
	return nil
}

// createForeignHookSessionStoreParent creates the folder that holds the
// accounts' private session stores (and their removal locks) when it is
// missing: 0700 and owned like the data directory dataDir, the gateway
// service. A folder that exists is left as it is.
func createForeignHookSessionStoreParent(dataDir, dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a folder", dir)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	info, err := os.Lstat(dataDir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok {
		return fmt.Errorf("%s is not a folder", dataDir)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		return err
	}
	return os.Lchown(dir, int(st.Uid), int(st.Gid))
}

// PublishedSessionKeysLockPath is the key lock of the standalone lifecycle
// folder lifecycleDir: the lifecycle's own lock (enterpriseunix holds it
// exclusively for its whole run), which only root can reach.
func PublishedSessionKeysLockPath(lifecycleDir string) string {
	return filepath.Join(lifecycleDir, "lifecycle.lock")
}

// publishedSessionKeysLockGuardianCreates is false: the key lock is the
// lifecycle's own, which only a lifecycle run makes (an uninstall that
// leaves the lifecycle folder empty removes it with the folder).
const publishedSessionKeysLockGuardianCreates = false

// openPublishedSessionKeysLockFile opens the key lock, never through a
// link; read access is enough for a flock.
func openPublishedSessionKeysLockFile(path string, create bool) (*os.File, error) {
	if create {
		return os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	}
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
