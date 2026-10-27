// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package unixidentity

import (
	"context"
	"errors"
	"testing"
)

// rel-1-0-5 GAP-0029: only Open Directory's own "record not found" (dscl
// exit 56, eDSRecordNotFound, no output) says a deleted account is gone. A
// found record, a timeout, a run error or any other DS error says nothing,
// so the guardian keeps waiting as before.
func TestDSCLRecordNotFoundIsTheOnlyGoneAnswer(t *testing.T) {
	cases := []struct {
		name   string
		result commandResult
		err    error
		want   bool
	}{
		{"record not found", commandResult{exitCode: 56}, nil, true},
		{"record not found, blank output", commandResult{exitCode: 56, stdout: []byte("\n")}, nil, true},
		{"found", commandResult{exitCode: 0, stdout: []byte("UniqueID: 509\n")}, nil, false},
		{"exit 56 with a record", commandResult{exitCode: 56, stdout: []byte("UniqueID: 509\n")}, nil, false},
		{"another DS error", commandResult{exitCode: 14}, nil, false},
		{"timed out", commandResult{}, errors.New("unixidentity: dscl timed out"), false},
	}
	for _, tc := range cases {
		if got := dsclRecordNotFound(tc.result, tc.err); got != tc.want {
			t.Errorf("%s: dsclRecordNotFound = %v, want %v", tc.name, got, tc.want)
		}
	}
	for _, name := range []string{"", "a/b", "a b", "a:b"} {
		if AccountRecordGone(context.Background(), name) {
			t.Errorf("AccountRecordGone(%q) = true for an invalid name", name)
		}
	}
}
