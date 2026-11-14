// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Package fsres is the filesystem resolver step of the effect model: it follows
// links, junctions and short names for a lexically resolved target. It is the
// ONLY part of the effect pipeline that touches the filesystem or depends on
// the OS, kept separate so the pure effects package stays testable anywhere
// (EFFECTS.md section 3). This package provides the interface and an in-memory
// Fake; the real per-OS resolvers (os_posix.go, os_windows.go) and the
// hook-client-evidence resolver land with stream S8, not in this shadow step.
package fsres

import "github.com/defenseclaw/defenseclaw/internal/effects"

// Resolution is what the resolver learned about one path.
type Resolution struct {
	Physical string
	Link     effects.LinkState
	Exists   Tri
}

// Tri is a three-valued existence answer.
type Tri int

const (
	Unknown Tri = iota
	No
	Yes
)

// Resolver follows links for one lexically resolved absolute path under the
// given flavor. It never parses commands.
type Resolver interface {
	Resolve(path string, flavor effects.Flavor) Resolution
}

// Apply fills Physical and Link on every path target of a result, in place. A
// nil resolver leaves targets at LinkNotChecked (the shadow default). Apply is
// idempotent and never changes Path.
func Apply(res *effects.Result, r Resolver) {
	if r == nil || res == nil {
		return
	}
	for i := range res.Effects {
		t := &res.Effects[i].Target
		if t.Type != effects.TargetPath || t.Path == "" {
			continue
		}
		got := r.Resolve(t.Path, t.Flavor)
		if got.Physical != "" {
			t.Physical = got.Physical
		}
		t.Link = got.Link
	}
}

// Fake is an in-memory resolver for tests: Links maps a lexical path to its
// physical target; Present lists paths known to exist.
type Fake struct {
	Links   map[string]string
	Present map[string]bool
}

// Resolve implements Resolver.
func (f Fake) Resolve(path string, flavor effects.Flavor) Resolution {
	r := Resolution{Link: effects.LinkNone, Exists: Unknown}
	if f.Present != nil {
		if f.Present[path] {
			r.Exists = Yes
		} else {
			r.Exists = No
		}
	}
	if f.Links != nil {
		if phys, ok := f.Links[path]; ok {
			r.Physical = phys
			r.Link = effects.LinkFollowed
		}
	}
	return r
}
