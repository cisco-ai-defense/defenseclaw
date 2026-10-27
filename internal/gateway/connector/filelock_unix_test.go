//go:build !windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// An old release unlinks its lock after releasing flock. A new holder that
// opened the old inode while waiting must retry on the new pathname.
func TestFileLockRetriesAfterLegacyWriterUnlinksContendedInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime")
	lockPath := path + ".lock"
	legacy, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if err := syscall.Flock(int(legacy.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	newLockReady := make(chan *os.File, 1)
	done := make(chan error, 1)
	go func() {
		done <- withFileLock(path, func() error {
			newLock := <-newLockReady
			if err := syscall.Flock(int(newLock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
				_ = syscall.Flock(int(newLock.Fd()), syscall.LOCK_UN)
				return errors.New("callback locked the unlinked inode; current path was unlocked")
			} else if !errors.Is(err, syscall.EWOULDBLOCK) {
				return err
			}
			return nil
		})
	}()
	// Give the contender time to open the legacy inode and wait on flock.
	time.Sleep(150 * time.Millisecond)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	newLock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer newLock.Close()
	newLockReady <- newLock
	if err := syscall.Flock(int(legacy.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("contender did not retry the current lock pathname")
	}
}
