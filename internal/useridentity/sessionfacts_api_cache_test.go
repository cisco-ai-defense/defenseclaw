// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import "testing"

type populatedAPICacheOps struct {
	lookup string
	closed bool
}

func (*populatedAPICacheOps) init() uintptr                  { return 1 }
func (*populatedAPICacheOps) freeContext(uintptr)            {}
func (o *populatedAPICacheOps) defaultCache(uintptr) uintptr { o.lookup = "default"; return 2 }
func (o *populatedAPICacheOps) namedCache(_ uintptr, name string) uintptr {
	o.lookup = name
	return 3
}
func (o *populatedAPICacheOps) close(uintptr, uintptr) { o.closed = true }
func (*populatedAPICacheOps) principal(_ uintptr, cache uintptr) string {
	if cache == 2 {
		return "alice@corp.example"
	}
	return "bob@corp.example"
}

func TestAPIPrincipalPopulatedDefaultAndNamedParity(t *testing.T) {
	for _, tc := range []struct {
		name, cacheName, wantPrincipal, wantLookup string
	}{
		{"platform default", "", "alice@CORP.EXAMPLE", "default"},
		{"bare environment", "API:", "alice@CORP.EXAMPLE", "default"},
		{"explicit name", "example-cache", "bob@CORP.EXAMPLE", "example-cache"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cacheName := tc.cacheName
			if cacheName == "API:" {
				kind, residual := SplitCCacheName(cacheName)
				if kind != CCacheAPI {
					t.Fatalf("cache kind = %q; want API", kind)
				}
				cacheName = residual
			}
			ops := new(populatedAPICacheOps)
			principal, settled := readAPIPrincipalWithOps(cacheName, ops)
			if principal != tc.wantPrincipal || !settled || ops.lookup != tc.wantLookup || !ops.closed {
				t.Fatalf("principal = %q, settled=%v, lookup=%q, closed=%v; want %q via %q",
					principal, settled, ops.lookup, ops.closed, tc.wantPrincipal, tc.wantLookup)
			}
		})
	}
}
