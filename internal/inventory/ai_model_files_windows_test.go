// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import "testing"

func TestModelPathWithinWindowsIsCaseInsensitiveAndStrictlyNested(t *testing.T) {
	for _, tc := range []struct {
		name   string
		path   string
		parent string
		want   bool
	}{
		{
			name:   "differently cased drive and components",
			path:   `c:\USERS\ALICE\.CACHE\HUGGINGFACE\hub\models--Qwen\model.gguf`,
			parent: `C:\Users\Alice\.cache\huggingface\HUB`,
			want:   true,
		},
		{
			name:   "equal path is not within itself",
			path:   `c:\USERS\ALICE\.CACHE\HUGGINGFACE\hub`,
			parent: `C:\Users\Alice\.cache\huggingface\HUB`,
			want:   false,
		},
		{
			name:   "ancestor is not within child",
			path:   `C:\Users\Alice\.cache\huggingface`,
			parent: `c:\users\alice\.CACHE\HUGGINGFACE\hub`,
			want:   false,
		},
		{
			name:   "sibling prefix is not within parent",
			path:   `C:\Users\Alice\.cache\huggingface-backup\model.gguf`,
			parent: `c:\users\alice\.CACHE\HUGGINGFACE`,
			want:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := modelPathWithin(tc.path, tc.parent); got != tc.want {
				t.Fatalf("modelPathWithin(%q, %q) = %t, want %t", tc.path, tc.parent, got, tc.want)
			}
		})
	}
}
