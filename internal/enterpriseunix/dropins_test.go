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

package enterpriseunix

import (
	"slices"
	"testing"
)

// GAP-1459: systemd decodes quotes and C escapes in Environment= and joins
// continuation lines, but the drop-in check read the raw text, so an escaped
// or split DEFENSECLAW_CONFIG passed as a site setting.
func TestDropInChangesDecodesSystemdEnvironmentSyntax(t *testing.T) {
	for _, tc := range []struct {
		body string
		want []string
	}{
		{`Environment=DEFENSECLAW\x5fCONFIG=/etc/weak.yaml`, []string{"Environment=DEFENSECLAW_CONFIG"}},
		{`Environment=DEFENSECLAW\137HOME=/tmp/x`, []string{"Environment=DEFENSECLAW_HOME"}},
		{`Environment=DEFENSECLAW"_"CONFIG=/etc/weak.yaml`, []string{"Environment=DEFENSECLAW_CONFIG"}},
		{`Environment="HTTPS_PROXY=http://p:3128" 'LD\x5fPRELOAD=/x.so'`, []string{"Environment=LD_PRELOAD"}},
		{"Environment=A=1 \\\n# note\n  Restart=always DEFENSECLAW_CONFIG=/etc/weak.yaml", []string{"Environment=DEFENSECLAW_CONFIG"}},
		{"Environment= \\\n", []string{dropInEnvironmentReset}},
		{`PassEnvironment=DEFENSECLAW\x5fCONFIG`, []string{"PassEnvironment"}},
		{`EnvironmentFile=-/etc/weak\x2eenv`, []string{"EnvironmentFile"}},
		{`Environment="HTTPS_PROXY=http://proxy:3128 x" NO\x5fPROXY=localhost`, nil},
		{`Environment="NOTE=a DEFENSECLAW_CONFIG=b"`, nil},
	} {
		if got := dropInChanges([]byte("[Service]\n" + tc.body + "\n")); !slices.Equal(got, tc.want) {
			t.Errorf("dropInChanges(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}
