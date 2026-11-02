// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const hookAPIACLInspectionTimeout = 5 * time.Second

// errHookAPIACLInspectionTimeout marks an ACL inspection that did not finish
// within its bound. It is transient: the inspection is retried once and a
// timeout is never cached.
var errHookAPIACLInspectionTimeout = errors.New("ACL inspection timed out")

func hookAPIInspectDirectoryACL(ctx context.Context, path string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/bin/ls", "-lde", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	return cmd.Output()
}

func hookAPIValidateDirectoryACL(path string) error {
	return hookAPIACLVerdicts.validate(path, hookAPIACLInspectionTimeout, hookAPIDirectoryIdentity, hookAPIInspectDirectoryACL)
}

func hookAPIValidateDirectoryACLWithInspector(path string, timeout time.Duration, inspect func(context.Context, string) ([]byte, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := inspect(ctx, path)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("inspect macOS ACL for %s: %w after %s", path, errHookAPIACLInspectionTimeout, timeout)
		}
		return fmt.Errorf("inspect macOS ACL for %s: %w", path, err)
	}
	// The managed rule judges effective write authority for principals other
	// than root, wheel and admin, and leaves read, deny and inherit-only
	// entries alone.
	return managed.JudgeDarwinACLOutput(path, output)
}

// hookAPIDirectoryStamp is what a cached ACL verdict is bound to: the
// folder's device and inode, and its modification and status-change times.
// Any ACL, mode or owner change moves the status-change time, and replacing
// the folder changes the inode, so either invalidates the verdict.
type hookAPIDirectoryStamp struct {
	dev   int64
	ino   uint64
	mtime unix.Timespec
	ctime unix.Timespec
}

func hookAPIDirectoryIdentity(path string) (hookAPIDirectoryStamp, bool) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return hookAPIDirectoryStamp{}, false
	}
	return hookAPIDirectoryStamp{
		dev:   int64(st.Dev),
		ino:   st.Ino,
		mtime: st.Mtim,
		ctime: st.Ctim,
	}, true
}

const hookAPIACLVerdictCacheSize = 256

// hookAPIACLVerdictCache remembers folders whose ACL passed the verdict. Every
// hook request walks the token location's folder chain; without the cache that
// is one /bin/ls fork per folder per request, and an EDR that scans process
// launches can push one past its timeout and reject the request. Only passing
// verdicts are cached, and only while the folder's identity is unchanged, so a
// failing or changed folder is always inspected again.
type hookAPIACLVerdictCache struct {
	mu      sync.Mutex
	max     int
	passing map[string]hookAPIDirectoryStamp
}

var hookAPIACLVerdicts = &hookAPIACLVerdictCache{max: hookAPIACLVerdictCacheSize}

func (c *hookAPIACLVerdictCache) validate(
	path string,
	timeout time.Duration,
	identify func(string) (hookAPIDirectoryStamp, bool),
	inspect func(context.Context, string) ([]byte, error),
) error {
	path = filepath.Clean(path)
	before, identified := identify(path)
	if identified && c.passed(path, before) {
		return nil
	}
	err := hookAPIValidateDirectoryACLWithInspector(path, timeout, inspect)
	if errors.Is(err, errHookAPIACLInspectionTimeout) {
		err = hookAPIValidateDirectoryACLWithInspector(path, timeout, inspect)
	}
	if err != nil {
		c.forget(path)
		return err
	}
	if after, ok := identify(path); identified && ok && after == before {
		c.remember(path, after)
	}
	return nil
}

func (c *hookAPIACLVerdictCache) passed(path string, identity hookAPIDirectoryStamp) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.passing[path]
	return ok && cached == identity
}

func (c *hookAPIACLVerdictCache) remember(path string, identity hookAPIDirectoryStamp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.passing == nil {
		c.passing = map[string]hookAPIDirectoryStamp{}
	}
	if _, exists := c.passing[path]; !exists && len(c.passing) >= c.max {
		c.passing = map[string]hookAPIDirectoryStamp{}
	}
	c.passing[path] = identity
}

func (c *hookAPIACLVerdictCache) forget(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.passing, path)
}
