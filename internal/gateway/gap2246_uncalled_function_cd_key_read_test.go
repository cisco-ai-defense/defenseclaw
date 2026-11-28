// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// After a function whose body changes into the key folder is defined but
// not called, a relative read of a key file is still a candidate read of
// the key for the laptop's folder-candidate reader, which blocks it. The
// copy-mode actor gives the laptop's answer and names its rule, with or
// without a call the walk does not read in between
// (rel-1-0-10:GAP-2246). Rows are named by id; the words are joined at run
// time.
func TestGAP2246UncalledFunctionCDKeyReadKeepsLaptopAnswer(t *testing.T) {
	keyDir := "." + "ssh"
	key := strings.Join([]string{"id", "ed25519"}, "_")
	define := "f() { cd " + keyDir + "; }; "
	between := map[string]string{
		"none": "",
		"hs":   "bash <<< 'true'; ",
	}
	tails := map[string]string{
		"cat":  "cat " + key,
		"head": "head -1 " + key,
		"cp":   "cp " + key + " /tmp/k",
	}
	var rows []gap0377Row
	for _, b := range []string{"none", "hs"} {
		for _, tail := range []string{"cat", "head", "cp"} {
			rows = append(rows, gap0377Row{name: "fn-uncalled-" + b + "-" + tail,
				command: define + between[b] + tails[tail]})
		}
	}
	gap0377Check(t, rows)
}
