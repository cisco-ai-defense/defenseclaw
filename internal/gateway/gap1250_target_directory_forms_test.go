// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strconv"
	"testing"
)

// TestGAP1250TargetDirectoryForms pins how the reading spells each source
// of a target-directory call (rel-1-0-10:GAP-1250): one move or copy per
// source onto DIR\<base>, the option values that are no source left out,
// MSYS mounts and the drive home spelled as drive paths, and no form for a
// call without a target directory or with a folder of no static value. A
// folder or source with a glob character Bash would expand is read as
// written when it matches nothing, and a source whose name the call does
// not fix ("$X", a glob, $(ls x)) lists the places it may land on, each
// state name its base may match and one name it surely matches, for the
// unknown tier; a fixed base ("$D/config.yaml") is a form
// (rel-1-0-10:GAP-1260).
func TestGAP1250TargetDirectoryForms(t *testing.T) {
	const home = `C:\Users\Alice`
	rows := []struct {
		command string
		want    []string
		unknown []string // places a source of unknown name may land on (a subset is listed)
	}{
		{`mv -t "$HOME\.defenseclaw" config.yaml`,
			[]string{`Move-Item -LiteralPath 'config.yaml' -Destination 'C:/Users/Alice\.defenseclaw\config.yaml'`}, nil},
		{`cp --target-directory=/c/x a/b.txt c`, []string{
			`Copy-Item -LiteralPath 'a/b.txt' -Destination 'C:/x\b.txt'`,
			`Copy-Item -LiteralPath 'c' -Destination 'C:/x\c'`}, nil},
		{`install -m 600 -t ~/d f`, []string{`Copy-Item -LiteralPath 'f' -Destination 'C:/Users/Alice/d\f'`}, nil},
		{`ln -st'C:\d' "it's"`, []string{`Copy-Item -LiteralPath 'it''s' -Destination 'C:\d\it''s'`}, nil},
		{`mv a b`, nil, nil},
		{`mv -t "$X" config.yaml`, nil, nil},
		{`mv -t"$X" "$Y"`, nil, nil},
		{`mv -t d "$X" config.yaml`, []string{`Move-Item -LiteralPath 'config.yaml' -Destination 'd\config.yaml'`},
			[]string{`d\config.yaml`, `d\.env`, `d\policies`}},
		{`echo mv -t d f`, nil, nil},
		{`mv -t //?/C:/x config.yaml`, []string{`Move-Item -LiteralPath 'config.yaml' -Destination '//?/C:/x\config.yaml'`}, nil},
		{`mv --target-directory=//?/C:/x/ f`, []string{`Move-Item -LiteralPath 'f' -Destination '//?/C:/x\f'`}, nil},
		{`cp -t d *.txt $(ls e) "$@"`, nil, []string{`d\.txt`, `d\config.yaml`}},
		{`mv --suffix="$S" -t d f`, []string{`Move-Item -LiteralPath 'f' -Destination 'd\f'`}, nil},
		{`mv -t d "$F.txt" 'conf'*.y?ml`, nil, []string{`d\.txt`, `d\config.yaml`, `d\conf.yxml`}},
		{`cp -t d "$D/config.yaml" "$D"/x/`, []string{`Copy-Item -LiteralPath 'config.yaml' -Destination 'd\config.yaml'`,
			`Copy-Item -LiteralPath 'x' -Destination 'd\x'`}, nil},
		{`mv -t d x"$F"`, nil, []string{`d\config.yaml`, `d\policies`}},
	}
	for _, row := range rows {
		got, bounded := targetDirectoryForms(row.command, home)
		listed := !slices.ContainsFunc(row.unknown, func(landing string) bool {
			return !slices.Contains(got.unknownLandings, landing)
		})
		if bounded || !slices.Equal(got.forms, row.want) || !listed || row.unknown == nil && got.unknownLandings != nil {
			t.Errorf("%s: forms %q unknown %q bounded %v, want %q unknown %q",
				row.command, got.forms, got.unknownLandings, bounded, row.want, row.unknown)
		}
	}
	many := "mv -t d"
	for index := range maxTargetDirectoryForms + 1 {
		many += " f" + strconv.Itoa(index)
	}
	if _, bounded := targetDirectoryForms(many, home); !bounded {
		t.Errorf("%d sources: not bounded", maxTargetDirectoryForms+1)
	}
}
