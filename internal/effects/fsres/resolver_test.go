// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package fsres

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func TestApplyFollowsFakeLinksAndSetsState(t *testing.T) {
	r := effects.Result{Effects: []effects.Effect{
		{Kind: effects.KindWrite, Target: effects.Target{Type: effects.TargetPath, Path: "/home/u/proj/link", Flavor: effects.FlavorPOSIX, Link: effects.LinkNotChecked}},
		{Kind: effects.KindRead, Target: effects.Target{Type: effects.TargetPath, Path: "/home/u/plain", Flavor: effects.FlavorPOSIX, Link: effects.LinkNotChecked}},
	}}
	fake := Fake{
		Links:   map[string]string{"/home/u/proj/link": "/home/u/.ssh/authorized_keys"},
		Present: map[string]bool{"/home/u/plain": true},
	}
	Apply(&r, fake)

	if got := r.Effects[0].Target.Physical; got != "/home/u/.ssh/authorized_keys" {
		t.Errorf("link not followed: physical=%q", got)
	}
	if r.Effects[0].Target.Link != effects.LinkFollowed {
		t.Errorf("link state = %q, want followed", r.Effects[0].Target.Link)
	}
	if r.Effects[1].Target.Link != effects.LinkNone {
		t.Errorf("plain path link state = %q, want none", r.Effects[1].Target.Link)
	}
	if r.Effects[1].Target.Physical != "" {
		t.Errorf("plain path should get no physical rewrite")
	}
}

func TestApplyNilResolverLeavesNotChecked(t *testing.T) {
	r := effects.Result{Effects: []effects.Effect{
		{Kind: effects.KindRead, Target: effects.Target{Type: effects.TargetPath, Path: "/x", Link: effects.LinkNotChecked}},
	}}
	Apply(&r, nil)
	if r.Effects[0].Target.Link != effects.LinkNotChecked {
		t.Errorf("nil resolver must leave not_checked, got %q", r.Effects[0].Target.Link)
	}
}
