// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"
)

// TestSourcedWriterWithArgumentsIsBlockedOnEveryRoute: the first word after
// . or source is the script and the words after it are its positional
// parameters, so a sourced script is the same file with or without them,
// as it is for bash. A write it makes to the keys file is blocked by a
// per-user gateway and by a managed one, which judges the hook client
// reading, whether the name is a full path, $HOME, ~ or relative, from the
// project or the home and through folder links; the ordinary script with the
// same arguments is allowed (rel-1-0-6:GAP-1068).
func TestSourcedWriterWithArgumentsIsBlockedOnEveryRoute(t *testing.T) {
	for _, links := range []int{0, 3} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			dir := "live"
			if links > 0 {
				dir = "d"
			}
			var rows []r106Reader2Row
			for _, r := range [][2]string{
				{"project", ". {H}/chain/" + dir + "/%s a"},
				{"home", "source {H}/chain/" + dir + "/%s a b"},
				{"project", ". ~/chain/" + dir + "/%s then stop"},
				{"home", "source $HOME/chain/" + dir + "/%s x"},
				{"project", ". ../chain/" + dir + "/%s a"},
				{"home", "source ./chain/" + dir + "/%s a"},
				{"project", `bash -c ". ~/chain/` + dir + `/%s a"`},
			} {
				rows = append(rows,
					r106Reader2Row{r[1] + " writer", r[0], fmt.Sprintf(r[1], "wk.sh"), "block"},
					r106Reader2Row{r[1] + " ordinary", r[0], fmt.Sprintf(r[1], "ok.sh"), "allow"})
			}
			r106Reader2CheckWith(t, rows, func(t *testing.T, f b36ManagedHookFixture) { homeScriptFolder(t, f, links) })
		})
	}
}
