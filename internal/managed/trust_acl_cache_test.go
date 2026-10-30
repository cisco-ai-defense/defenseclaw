//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"testing"
)

type fakeACLPath struct {
	key      aclVerdictKey
	statErr  error
	verdict  error
	reads    int
	duringFn func()
}

func (f *fakeACLPath) stat(string) (aclVerdictKey, error) { return f.key, f.statErr }

func (f *fakeACLPath) inspect(string) error {
	f.reads++
	if f.duringFn != nil {
		f.duringFn()
	}
	return f.verdict
}

func TestACLVerdictCacheReadsAnUnchangedCleanPathOnce(t *testing.T) {
	var cache aclVerdictCache
	p := &fakeACLPath{key: aclVerdictKey{path: "/opt/x", ino: 7, ctime: 100}}
	for i := 0; i < 3; i++ {
		if err := cache.check("/opt/x", p.stat, p.inspect); err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
	}
	if p.reads != 1 {
		t.Fatalf("ACL read %d times for an unchanged clean path, want 1", p.reads)
	}
}

func TestACLVerdictCacheReadsAgainAfterAMetadataChange(t *testing.T) {
	var cache aclVerdictCache
	p := &fakeACLPath{key: aclVerdictKey{path: "/opt/x", ino: 7, ctime: 100}}
	_ = cache.check("/opt/x", p.stat, p.inspect)
	// chmod +a sets the inode change time; the next check reads the ACL and
	// sees the write grant.
	p.key.ctime = 101
	p.verdict = newTrustVerdict("/opt/x has write-capable macOS ACL entry")
	if err := cache.check("/opt/x", p.stat, p.inspect); err == nil {
		t.Fatal("write grant added after a clean read was not seen")
	}
	// A path replaced by another file has another inode.
	p.key.ctime, p.key.ino = 100, 8
	if err := cache.check("/opt/x", p.stat, p.inspect); err == nil {
		t.Fatal("replaced path with a write grant was not seen")
	}
	if p.reads != 3 {
		t.Fatalf("reads = %d, want 3", p.reads)
	}
}

func TestACLVerdictCacheNeverKeepsARefusalOrAnError(t *testing.T) {
	var cache aclVerdictCache
	p := &fakeACLPath{key: aclVerdictKey{path: "/opt/x", ino: 7, ctime: 100}, verdict: errors.New("inspect macOS ACL: boom")}
	for i := 0; i < 2; i++ {
		if err := cache.check("/opt/x", p.stat, p.inspect); err == nil {
			t.Fatalf("check %d: read error swallowed", i)
		}
	}
	if p.reads != 2 {
		t.Fatalf("reads = %d, want 2 (an error is not kept)", p.reads)
	}
}

func TestACLVerdictCacheDoesNotKeepAVerdictReadWhileTheMetadataChanged(t *testing.T) {
	var cache aclVerdictCache
	p := &fakeACLPath{key: aclVerdictKey{path: "/opt/x", ino: 7, ctime: 100}}
	p.duringFn = func() { p.key.ctime = 101 }
	_ = cache.check("/opt/x", p.stat, p.inspect)
	p.duringFn = nil
	p.verdict = newTrustVerdict("/opt/x has write-capable macOS ACL entry")
	if err := cache.check("/opt/x", p.stat, p.inspect); err == nil {
		t.Fatal("verdict read while the ACL changed was kept")
	}
}

func TestACLVerdictCacheReadsEveryTimeWhenThePathCannotBeStated(t *testing.T) {
	var cache aclVerdictCache
	p := &fakeACLPath{statErr: errors.New("lstat: denied")}
	_ = cache.check("/opt/x", p.stat, p.inspect)
	_ = cache.check("/opt/x", p.stat, p.inspect)
	if p.reads != 2 {
		t.Fatalf("reads = %d, want 2", p.reads)
	}
}
