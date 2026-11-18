// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bufio"
	"bytes"
	"errors"
	"path"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// kitMountRefusal says which of DefenseClaw's paths a mount of the actor
// hides, "" when none does (GAP-0368, GAP-0439). Admission refuses a
// template whose volume mounts touch the attested paths, but it cannot see
// a symlink in the image or in an image volume (a mount at /work/x where
// /work/x points at /etc/claude-code lands on /etc/claude-code). mountinfo
// (the format of /proc/self/mountinfo) names where each mount really is, so
// the relay refuses the agent when a mount is at, above or below
//   - a protected path: every root-owned file the template build attested
//     and the folders holding them (relay.protected, kit.ProtectedPaths:
//     the connector's managed settings, its hook registration, the kit
//     library and /etc/defenseclaw; the last two also when the
//     configuration predates the list), or
//   - a guarded HOME folder (Antigravity's ~/.gemini): a mount above one
//     (HOME itself) hides it as surely as one on it.
//
// A mount in a folder whose files programs load (kit.LoadDirs: /usr, /etc,
// /lib, /bin, /sbin), other than a file the runtime binds
// (kit.RuntimeMountFiles), is refused as well.
//
// The root mount is the image itself. A table without it is not the
// actor's mount table: errNoRootMount (GAP-0443), and the relay refuses as
// for an unreadable one. A second mount at / hides the whole image and is
// refused as a mount over every protected path ("/", GAP-0510).
func kitMountRefusal(mountinfo []byte, protected, guarded []string) (string, error) {
	paths := []string{kit.LibDir, path.Dir(kit.ConfigPath)}
	for _, p := range append(append([]string{}, protected...), guarded...) {
		if path.IsAbs(p) && path.Clean(p) != "/" {
			paths = append(paths, path.Clean(p))
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(mountinfo))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	root := false
	hidden := ""
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		mp := path.Clean(unescapeMount(f[4]))
		if mp == "/" {
			// The first root mount is the image. Another one at / (an image
			// volume reached through a symlink to /) lies over the image and
			// every path in it (GAP-0510).
			if root && hidden == "" {
				hidden = "/"
			}
			root = true
			continue
		}
		for _, k := range paths {
			if hidden == "" && (pathWithin(mp, k) || pathWithin(k, mp)) {
				hidden = k
			}
		}
		// A data mount that lands in a system folder (an image symlink
		// below WORKDIR into /usr/lib/x86_64-linux-gnu, or onto
		// /etc/ld.so.preload) changes what every program loads; admission
		// sees only the mount path (GAP-0441, GAP-0576).
		if hidden == "" && kit.InLoadDir(mp) {
			hidden = mp
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if !root {
		return "", errNoRootMount
	}
	return hidden, nil
}

// errNoRootMount is a mount table without the root mount (GAP-0443).
var errNoRootMount = errors.New("the mount table has no root mount")

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
