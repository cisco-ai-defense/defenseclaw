// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"regexp"
)

// maskShape finds the capturable issuer prefixes followed by a credential
// body, with no word-boundary requirement: in JSON a value can follow an
// escape such as \n, and in protobuf a length byte. Masking more than
// strictly needed only blanks a few more characters of telemetry.
var maskShape = regexp.MustCompile(`(sk-ant-|sk-proj-|sk-svcacct-|sk-|gh[pousr]_|github_pat_|xox[abprs]-|AIza|[rs]k_live_)([0-9A-Za-z_-]{20,})`)

// MaskCapturable returns b with the body of every credential with a
// capturable issuer shape replaced by '*' (the prefix is kept, the length
// is unchanged), and whether anything was masked. A body of one repeated
// character is a placeholder and is left alone.
func MaskCapturable(b []byte) ([]byte, bool) {
	locs := maskShape.FindAllSubmatchIndex(b, -1)
	if len(locs) == 0 {
		return b, false
	}
	out := append([]byte(nil), b...)
	changed := false
	for _, l := range locs {
		body := out[l[4]:l[5]]
		same := true
		for _, c := range body {
			if c != body[0] {
				same = false
				break
			}
		}
		if same {
			continue
		}
		for i := l[4]; i < l[5]; i++ {
			out[i] = '*'
		}
		changed = true
	}
	return out, changed
}
