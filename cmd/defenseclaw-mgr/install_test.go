// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
)

func TestNormalizeFlags(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "MSI slash-colon flags translate to GNU long-form",
			in:   []string{"/config:C:\\stage\\config.yaml", "/manifest=C:\\stage\\targets.yaml"},
			want: []string{"--config=C:\\stage\\config.yaml", "--manifest=C:\\stage\\targets.yaml"},
		},
		{
			name: "boolean slash flag has no value",
			in:   []string{"/quiet", "/norestart"},
			want: []string{"--quiet", "--norestart"},
		},
		{
			name: "already-normalized flags pass through unchanged",
			in:   []string{"--config", "path", "-h"},
			want: []string{"--config", "path", "-h"},
		},
		{
			name: "empty slice",
			in:   nil,
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeFlags(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("normalizeFlags(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
