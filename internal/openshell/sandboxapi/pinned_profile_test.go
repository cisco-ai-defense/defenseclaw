// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"strings"
	"testing"
)

// The refusal of a sandbox whose floor is pinned to the profile it was
// created under names that profile, says it is pinned and names the
// profile assigned now; the quote names the pinned one (GAP-0285).
func TestAccessRefusalNamesTheCreatePinnedProfile(t *testing.T) {
	label := PinnedProfileLabel("fcr-strict", "fcr-loose")
	if label != "fcr-strict, pinned when this sandbox was created; you are now assigned fcr-loose" {
		t.Fatalf("label = %q", label)
	}
	got := AccessRefused("egress_block", "github.com", label, "fr1a", "it-security@example.com")
	for _, want := range []string{
		"github.com is blocked by your organization (profile fcr-strict, pinned when this sandbox was created, rule egress_block; you are now assigned fcr-loose).",
		"Quote: profile fcr-strict, rule egress_block, host github.com, sandbox fr1a.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("refusal %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "Quote: profile fcr-loose") {
		t.Fatalf("the quote names the current profile: %q", got)
	}
	// Without a pin, the refusal is as before.
	plain := AccessRefused("egress_block", "github.com", PinnedProfileLabel("", "fcr-loose"), "fr1a", "it-security@example.com")
	if !strings.Contains(plain, "(profile fcr-loose, rule egress_block)") || strings.Contains(plain, "pinned") {
		t.Fatalf("unpinned refusal: %q", plain)
	}
	if PinnedProfileLabel("same", "same") != "same" {
		t.Fatal("a pin on the current profile is named twice")
	}
}
