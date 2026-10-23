// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// ErrPathNotLocal reports a path that cannot be shown to stay on a local
// disk: a UNC, device or volume-GUID spelling, a drive that is not a local
// disk volume, or a link whose target is one of those.
var ErrPathNotLocal = errors.New("path is not proven to stay on a local disk")

const (
	reparseTagMountPoint = 0xA0000003
	reparseTagSymlink    = 0xA000000C
	// reparseTagNameSurrogate marks a tag that names another file system
	// entry (a link): Windows follows it when it opens the path.
	reparseTagNameSurrogate = 0x20000000
	symlinkFlagRelative     = 1
)

// reparseLink is the target a symbolic link or junction names, read from its
// substitute name: the one Windows follows. The print name is display text
// a link's creator chooses freely and is never trusted.
type reparseLink struct {
	target   string
	relative bool
}

// parseReparseLink decodes an FSCTL_GET_REPARSE_POINT buffer. surrogate is
// false for a reparse point that Windows opens in place (a cloud file
// placeholder, a deduplicated file). Any other name surrogate than a
// symbolic link or junction, and a malformed buffer, is ErrPathNotLocal.
func parseReparseLink(data []byte) (link reparseLink, surrogate bool, err error) {
	if len(data) < 8 {
		return link, false, fmt.Errorf("%w: short reparse buffer", ErrPathNotLocal)
	}
	tag := binary.LittleEndian.Uint32(data[0:4])
	if tag&reparseTagNameSurrogate == 0 {
		return link, false, nil
	}
	size := int(binary.LittleEndian.Uint16(data[4:6]))
	if size > len(data)-8 {
		return link, true, fmt.Errorf("%w: truncated reparse buffer", ErrPathNotLocal)
	}
	body := data[8 : 8+size]
	var header int
	switch tag {
	case reparseTagSymlink:
		header = 12
	case reparseTagMountPoint:
		header = 8
	default:
		return link, true, fmt.Errorf("%w: unsupported link type %#x", ErrPathNotLocal, tag)
	}
	if len(body) < header {
		return link, true, fmt.Errorf("%w: short link record", ErrPathNotLocal)
	}
	offset := int(binary.LittleEndian.Uint16(body[0:2]))
	length := int(binary.LittleEndian.Uint16(body[2:4]))
	names := body[header:]
	if length == 0 || offset%2 != 0 || length%2 != 0 || offset+length > len(names) {
		return link, true, fmt.Errorf("%w: malformed link target", ErrPathNotLocal)
	}
	units := make([]uint16, length/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(names[offset+2*i:])
	}
	link.target = string(utf16.Decode(units))
	if strings.ContainsRune(link.target, 0) {
		return reparseLink{}, true, fmt.Errorf("%w: link target contains NUL", ErrPathNotLocal)
	}
	link.relative = tag == reparseTagSymlink && binary.LittleEndian.Uint32(body[8:12])&symlinkFlagRelative != 0
	return link, true, nil
}

// ntDriveTarget converts an absolute link target in the NT namespace
// (\??\C:\dir) to its drive-letter form. Every other spelling (\??\UNC\,
// \??\Volume{...}, \Device\, \DosDevices\, GLOBALROOT) is refused: only a
// drive letter can be checked against the local disk volumes.
func ntDriveTarget(target string) (string, bool) {
	rest, ok := strings.CutPrefix(target, `\??\`)
	if !ok || len(rest) < 2 || rest[1] != ':' || !isASCIIDriveLetter(rest[0]) {
		return "", false
	}
	if len(rest) == 2 {
		rest += `\`
	}
	if rest[2] != '\\' || strings.Contains(rest[2:], ":") {
		return "", false
	}
	return rest, true
}

func isASCIIDriveLetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

// localDiskDevice reports whether a drive's DOS device target is a local
// disk volume (\Device\HarddiskVolumeN). Mapped network drives
// (\Device\LanmanRedirector, \Device\Mup), substituted drives (\??\...) and
// other devices are refused.
func localDiskDevice(target string) bool {
	const prefix = `\DEVICE\HARDDISKVOLUME`
	upper := strings.ToUpper(target)
	if !strings.HasPrefix(upper, prefix) || len(upper) == len(prefix) {
		return false
	}
	for _, char := range upper[len(prefix):] {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
