// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import "testing"

func TestNetworkShareRootWindows(t *testing.T) {
	for path, want := range map[string]string{
		`\\server\share\dir\f`:            `\\server\share`,
		`//www.example.org/c`:             `//www.example.org/c`,
		`\\?\UNC\server\share\f`:          `\\?\UNC\server\share`,
		`C:\Users\u\.ssh\authorized_keys`: "",
		`\\?\C:\Users\u`:                  "",
		`\\.\pipe\name`:                   "",
		`relative\path`:                   "",
	} {
		if got := networkShareRoot(path); got != want {
			t.Errorf("networkShareRoot(%q) = %q, want %q", path, got, want)
		}
	}
}
