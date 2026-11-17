// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
	"testing"
)

// TestGAP1250TargetDirectoryForms pins how the reading spells each source
// of a target-directory call (rel-1-0-10:GAP-1250): one move or copy per
// source onto DIR\<base>, the option values that are no source left out,
// MSYS mounts and the drive home spelled as drive paths, and no form for a
// call without a target directory or with a folder of no static value.
func TestGAP1250TargetDirectoryForms(t *testing.T) {
	const home = `C:\Users\Alice`
	rows := []struct {
		command string
		want    []string
	}{
		{`mv -t "$HOME\.defenseclaw" config.yaml`,
			[]string{`Move-Item -LiteralPath 'config.yaml' -Destination 'C:/Users/Alice\.defenseclaw\config.yaml'`}},
		{`cp --target-directory=/c/x a/b.txt c`, []string{
			`Copy-Item -LiteralPath 'a/b.txt' -Destination 'C:/x\b.txt'`,
			`Copy-Item -LiteralPath 'c' -Destination 'C:/x\c'`}},
		{`install -m 600 -t ~/d f`, []string{`Copy-Item -LiteralPath 'f' -Destination 'C:/Users/Alice/d\f'`}},
		{`ln -st'C:\d' "it's"`, []string{`Copy-Item -LiteralPath 'it''s' -Destination 'C:\d\it''s'`}},
		{`mv a b`, nil},
		{`mv -t "$X" config.yaml`, nil},
		{`mv -t d "$X" config.yaml`, []string{`Move-Item -LiteralPath 'config.yaml' -Destination 'd\config.yaml'`}},
		{`echo mv -t d f`, nil},
	}
	for _, row := range rows {
		got, bounded := targetDirectoryForms(row.command, home)
		if bounded || !slices.Equal(got, row.want) {
			t.Errorf("%s: forms %q bounded %v, want %q", row.command, got, bounded, row.want)
		}
	}
	many := "mv -t d" + strings.Repeat(" f", maxTargetDirectoryForms+1)
	if _, bounded := targetDirectoryForms(many, home); !bounded {
		t.Errorf("%d sources: not bounded", maxTargetDirectoryForms+1)
	}
}
