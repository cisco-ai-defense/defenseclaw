// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// An actor's chain store is a full audit store, and opening a new one runs
// every audit migration. SQLite parses that schema under process-wide locks,
// so on E5 50 actors started at once (CERT-110 J43) waited up to 15 s for
// their first chain call, past the kit's answer budget; the kit's resends of
// those calls are what substrate-1 GAP-0564 refused. The leader migrates one
// seed store per process and gives each new actor a copy of it: a new
// actor's first call costs a file copy and the checks of an open, not the
// migrations. The seed lives under chains/.seed/, which no actor key can
// name (atespaceRE refuses the dot), so load never takes it for an actor.
// Anything that goes wrong falls back to migrating the actor's own store.

// seedStale is how old another process's seed folder must be before a
// leader removes it: a leader that is stopping may still copy its own.
const seedStale = 10 * time.Minute

// seedRootDigest names no root scope: the seed only makes the root tables.
var seedRootDigest = strings.Repeat("0", 64)

type storeSeed struct {
	mu   sync.Mutex
	dir  string // this process's seed folder, "" until built
	path string
	err  error // the build failed: this process migrates every new store
}

func (s *Service) seedRoot() string { return filepath.Join(s.opts.Dir, "chains", ".seed") }

// seedFile returns the migrated seed store, building it on first use.
func (s *Service) seedFile() (string, error) {
	b := &s.seed
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.path != "" || b.err != nil {
		return b.path, b.err
	}
	root := s.seedRoot()
	if err := os.MkdirAll(root, 0o700); err != nil {
		b.err = err
		return "", err
	}
	if old, err := os.ReadDir(root); err == nil {
		for _, d := range old {
			if info, err := d.Info(); err == nil && time.Since(info.ModTime()) > seedStale {
				_ = os.RemoveAll(filepath.Join(root, d.Name()))
			}
		}
	}
	dir, err := os.MkdirTemp(root, "seed-")
	if err != nil {
		b.err = err
		return "", err
	}
	path := filepath.Join(dir, "store.db")
	st, err := audit.NewStore(path)
	if err == nil {
		if err = st.Init(); err == nil {
			// The actor window's tables too, which a store makes on its
			// first actor-scope call.
			_, err = st.ToolChainRootRepository(context.Background(), seedRootDigest)
		}
		err = errors.Join(err, st.Close())
	}
	if err == nil {
		// Close checkpoints the WAL: the seed is the main file alone.
		if _, werr := os.Stat(path + "-wal"); werr == nil {
			err = errors.New("the seed store kept a WAL file after it closed")
		}
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		s.warnf("chain store seed: %v; each new actor's store is migrated in place", err)
		b.err = err
		return "", err
	}
	b.dir, b.path = dir, path
	return path, nil
}

// seedStore writes a copy of the seed to path, the store file of a new
// actor that does not exist yet, and reports whether it did. A file that
// is there already is left as it is.
func (s *Service) seedStore(path string) bool {
	seed, err := s.seedFile()
	if err != nil {
		return false
	}
	if err := copyNewFile(seed, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			s.warnf("chain store seed for %s: %v; migrating it in place", strings.TrimSuffix(filepath.Base(path), ".db"), err)
		}
		return false
	}
	return true
}

// removeSeed removes this process's seed folder (Close).
func (s *Service) removeSeed() {
	b := &s.seed
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dir != "" {
		_ = os.RemoveAll(b.dir)
	}
	b.dir, b.path, b.err = "", "", errors.New("chain state closed")
}

// copyNewFile copies src to dst, which it creates (owner-only) and syncs.
// A dst that exists is an os.ErrExist and is not touched; a copy that fails
// part way is removed.
func copyNewFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(dst)
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
