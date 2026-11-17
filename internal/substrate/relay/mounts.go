// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bufio"
	"bytes"
	"path"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// kitMountRefusal says which of DefenseClaw's paths a mount of the actor
// hides, "" when none does (GAP-0368). Admission refuses a template whose
// volume mounts touch the kit's paths, but it cannot see a symlink in the
// image (a mount at /work/x where the image makes /work/x point at the
// kit's hook folder lands on the hook folder). mountinfo (the format of
// /proc/self/mountinfo) names where each mount really is, so the relay
// refuses the agent when a mount is at, above or below the kit library or
// /etc/defenseclaw, or at or below a guarded HOME folder (a mount above
// one hides it, which the guard refuses as a missing folder). The root
// mount is the image itself.
func kitMountRefusal(mountinfo []byte, guarded []string) string {
	kitPaths := []string{kit.LibDir, path.Dir(kit.ConfigPath)}
	sc := bufio.NewScanner(bytes.NewReader(mountinfo))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		mp := path.Clean(unescapeMount(f[4]))
		if mp == "/" {
			continue
		}
		for _, k := range kitPaths {
			if pathWithin(mp, k) || pathWithin(k, mp) {
				return k
			}
		}
		for _, g := range guarded {
			if g = path.Clean(g); pathWithin(mp, g) {
				return g
			}
		}
	}
	return ""
}

// unescapeMount undoes the octal escapes of a mountinfo path (\040 is a
// space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// pathWithin reports whether clean path p is dir or below it.
func pathWithin(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}
