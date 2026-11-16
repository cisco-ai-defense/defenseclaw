//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import "sync"

// aclVerdictCacheLimit bounds the clean verdicts kept; a full cache starts
// over.
const aclVerdictCacheLimit = 1024

// aclVerdictKey is a path and the inode metadata its ACL was read at.
type aclVerdictKey struct {
	path     string
	dev, ino uint64
	ctime    int64
	mode     uint32
	uid, gid uint32
}

// aclVerdictCache remembers the paths whose ACL was read and found clean,
// keyed by their inode metadata. Only a clean verdict is kept, and only when
// the metadata read before and after the ACL read agree, so an ACL changed
// while it was read is read again next time. A refusal or a read error is
// never kept.
type aclVerdictCache struct {
	mu    sync.Mutex
	clean map[aclVerdictKey]struct{}
}

func (c *aclVerdictCache) check(path string, stat func(string) (aclVerdictKey, error), inspect func(string) error) error {
	before, err := stat(path)
	if err != nil {
		return inspect(path)
	}
	c.mu.Lock()
	_, known := c.clean[before]
	c.mu.Unlock()
	if known {
		return nil
	}
	if err := inspect(path); err != nil {
		return err
	}
	if after, err := stat(path); err != nil || after != before {
		return nil
	}
	c.mu.Lock()
	if c.clean == nil || len(c.clean) >= aclVerdictCacheLimit {
		c.clean = make(map[aclVerdictKey]struct{})
	}
	c.clean[before] = struct{}{}
	c.mu.Unlock()
	return nil
}
