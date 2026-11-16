// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"
)

// reparseBuffer builds an FSCTL_GET_REPARSE_POINT answer for a symbolic
// link (tag reparseTagSymlink) or junction with separate substitute and
// print names, as a link's creator may write them. Each name is followed
// by a NUL, as Windows writes junctions.
func reparseBuffer(tag uint32, substitute, print string, relative bool) []byte {
	sub := append(utf16.Encode([]rune(substitute)), 0)
	prn := append(utf16.Encode([]rune(print)), 0)
	header := 8
	if tag == reparseTagSymlink {
		header = 12
	}
	body := make([]byte, header+2*(len(sub)+len(prn)))
	binary.LittleEndian.PutUint16(body[0:], 0)
	binary.LittleEndian.PutUint16(body[2:], uint16(2*(len(sub)-1)))
	binary.LittleEndian.PutUint16(body[4:], uint16(2*len(sub)))
	binary.LittleEndian.PutUint16(body[6:], uint16(2*(len(prn)-1)))
	if tag == reparseTagSymlink && relative {
		binary.LittleEndian.PutUint32(body[8:], symlinkFlagRelative)
	}
	for i, unit := range append(sub, prn...) {
		binary.LittleEndian.PutUint16(body[header+2*i:], unit)
	}
	out := make([]byte, 8, 8+len(body))
	binary.LittleEndian.PutUint32(out[0:], tag)
	binary.LittleEndian.PutUint16(out[4:], uint16(len(body)))
	return append(out, body...)
}

// Only the substitute name of a symbolic link or junction is followed, and
// only a drive-letter target is ever resolved: a network, device or volume
// target is refused whatever the print name shows.
func TestParseReparseLinkTargets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		data      []byte
		target    string
		relative  bool
		surrogate bool
		local     bool
		refused   bool
	}{
		{name: "junction to a drive path", data: reparseBuffer(reparseTagMountPoint, `\??\C:\Users\alice`, `C:\Users\alice`, false),
			target: `C:\Users\alice`, surrogate: true, local: true},
		{name: "symlink to a drive root", data: reparseBuffer(reparseTagSymlink, `\??\D:`, `D:`, false),
			target: `D:\`, surrogate: true, local: true},
		{name: "relative symlink", data: reparseBuffer(reparseTagSymlink, `..\alice`, `..\alice`, true),
			target: `..\alice`, relative: true, surrogate: true},
		{name: "symlink to a share", data: reparseBuffer(reparseTagSymlink, `\??\UNC\files\home\alice`, `\\files\home\alice`, false),
			surrogate: true},
		{name: "share behind a local print name", data: reparseBuffer(reparseTagSymlink, `\??\UNC\files\home\alice`, `C:\Users\alice`, false),
			surrogate: true},
		{name: "junction to a share", data: reparseBuffer(reparseTagMountPoint, `\??\UNC\files\home`, `C:\Users\alice`, false),
			surrogate: true},
		{name: "volume mount point", data: reparseBuffer(reparseTagMountPoint, `\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\`, ``, false),
			surrogate: true},
		{name: "device namespace", data: reparseBuffer(reparseTagSymlink, `\Device\Mup\files\home`, `C:\x`, false),
			surrogate: true},
		{name: "global root", data: reparseBuffer(reparseTagSymlink, `\??\GLOBALROOT\Device\Mup\files`, `C:\x`, false),
			surrogate: true},
		{name: "alternate stream", data: reparseBuffer(reparseTagSymlink, `\??\C:\Users\alice:stream`, ``, false),
			surrogate: true},
		{name: "unknown link type", data: reparseBuffer(0xA000001D, `\??\C:\x`, ``, false), surrogate: true, refused: true},
		{name: "truncated", data: reparseBuffer(reparseTagSymlink, `\??\C:\x`, ``, false)[:20], surrogate: true, refused: true},
		{name: "short", data: []byte{1, 2, 3}, refused: true},
		{name: "cloud placeholder opens in place", data: []byte{0x1a, 0x00, 0x00, 0x90, 0, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link, surrogate, err := parseReparseLink(tc.data)
			if tc.refused {
				if !errors.Is(err, ErrPathNotLocal) {
					t.Fatalf("err = %v, want ErrPathNotLocal", err)
				}
				return
			}
			if err != nil || surrogate != tc.surrogate {
				t.Fatalf("surrogate = %v, err = %v", surrogate, err)
			}
			if !surrogate {
				return
			}
			if tc.relative {
				if !link.relative || link.target != tc.target {
					t.Fatalf("link = %+v", link)
				}
				return
			}
			got, ok := ntDriveTarget(link.target)
			if ok != tc.local || got != tc.target {
				t.Fatalf("drive target of %q = %q, %v; want %q, %v", link.target, got, ok, tc.target, tc.local)
			}
		})
	}
}

// A drive counts as local only when its DOS device is a disk volume; a
// mapped share or a substituted path does not.
func TestLocalDiskDevice(t *testing.T) {
	for target, want := range map[string]bool{
		`\Device\HarddiskVolume3`:                         true,
		`\Device\HarddiskVolume12`:                        true,
		`\Device\LanmanRedirector\;Z:0000c1f2\files\home`: false,
		`\Device\Mup\;Z:\files\home`:                      false,
		`\??\C:\Users\alice`:                              false,
		`\Device\HarddiskVolume`:                          false,
		`\Device\HarddiskVolume3\..\Mup`:                  false,
		`\Device\CdRom0`:                                  false,
	} {
		if got := localDiskDevice(target); got != want {
			t.Errorf("localDiskDevice(%q) = %v, want %v", target, got, want)
		}
	}
}
