// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// windowsShareRoot is the network share volume a Windows path names, as the
// path spells it, and the server it names; "" for a drive path, a relative
// path and every device path that is not on the network redirector. Windows
// opens a share for each of these spellings (rel-1-0-10:GAP-1074):
//
//	\\server\share and //server/share, with any mix and number of leading
//	separators, and the WebDAV forms \\server@SSL\share, \\server@8443\share
//	\\?\UNC\server\share and \\.\UNC\server\share (either separator)
//	\??\UNC\server\share, the NT name Win32 passes through as it is
//	\\?\Global\UNC\server\share, \\.\Global\UNC\... (Global is the same namespace)
//	\\?\GLOBALROOT\Device\Mup\server\share, and \Device\LanmanRedirector,
//	\Device\WebDavRedirector, with or without the ;-prefixed parts a mapped
//	drive adds (\;Z:0000...\server\share), and GLOBALROOT\??\UNC\...,
//	GLOBALROOT\GLOBAL??\UNC\..., GLOBALROOT\DosDevices\UNC\...
//
// A share without its share name (\\server) is the server. It is a function
// of the text alone, on every host, so that tests on any host read the
// Windows spellings as Windows does.
func windowsShareRoot(path string) (root, server string) {
	if len(path) < 2 || !windowsSlash(path[0]) {
		return "", ""
	}
	if len(path) >= 4 && path[1] == '?' && path[2] == '?' && windowsSlash(path[3]) {
		return windowsDeviceShare(path, 4)
	}
	if !windowsSlash(path[1]) {
		return "", ""
	}
	if len(path) >= 3 && (path[2] == '?' || path[2] == '.') && (len(path) == 3 || windowsSlash(path[3])) {
		return windowsDeviceShare(path, 4)
	}
	return windowsUNCShare(path, 2)
}

// windowsDeviceShare reads the device namespace part of path from i (the
// part after \\?\, \\.\ or \??\) for the network redirector.
func windowsDeviceShare(path string, i int) (root, server string) {
	const (
		dosDevices = iota // \??\ (\GLOBAL??\): drive letters, UNC, Global, GLOBALROOT
		objectRoot        // GLOBALROOT: the root of the object namespace
	)
	space := dosDevices
	for i < len(path) {
		var elem string
		elem, i = windowsPathElement(path, i)
		switch space {
		case dosDevices:
			switch {
			case strings.EqualFold(elem, "UNC"):
				return windowsUNCShare(path, i)
			case strings.EqualFold(elem, "Global"):
			case strings.EqualFold(elem, "GLOBALROOT"):
				space = objectRoot
			default:
				return "", ""
			}
		case objectRoot:
			switch {
			case strings.EqualFold(elem, "??"), strings.EqualFold(elem, "GLOBAL??"), strings.EqualFold(elem, "DosDevices"):
				space = dosDevices
			case strings.EqualFold(elem, "Device"):
				device, next := windowsPathElement(path, i)
				if !windowsNetworkRedirector(device) {
					return "", ""
				}
				i = next
				// A mapped drive names its session as ;Z:<logon id> parts first.
				for {
					part, after := windowsPathElement(path, i)
					if !strings.HasPrefix(part, ";") {
						break
					}
					i = after
				}
				return windowsUNCShare(path, i)
			default:
				return "", ""
			}
		}
	}
	return "", ""
}

// windowsNetworkRedirector reports a device of \Device that opens files on
// other machines.
func windowsNetworkRedirector(device string) bool {
	for _, name := range []string{"Mup", "LanmanRedirector", "WebDavRedirector"} {
		if strings.EqualFold(device, name) {
			return true
		}
	}
	return false
}

// windowsUNCShare is the share whose server name begins at i (after any
// further separators): path up to the end of the share name, and the server.
func windowsUNCShare(path string, i int) (root, server string) {
	for i < len(path) && windowsSlash(path[i]) {
		i++
	}
	server, next := windowsPathElement(path, i)
	if server == "" {
		return "", ""
	}
	end := i + len(server)
	for next < len(path) && windowsSlash(path[next]) {
		next++
	}
	if share, _ := windowsPathElement(path, next); share != "" {
		end = next + len(share)
	}
	return path[:end], server
}

// windowsPathElement is the name of path that begins at i, and the index
// after its separator.
func windowsPathElement(path string, i int) (elem string, next int) {
	j := i
	for j < len(path) && !windowsSlash(path[j]) {
		j++
	}
	if j < len(path) {
		return path[i:j], j + 1
	}
	return path[i:j], j
}

func windowsSlash(c byte) bool { return c == '\\' || c == '/' }

// shareOfThisMachine reports a share root whose server is this machine:
// localhost, a loopback address, or a name of this host (the server part of
// a WebDAV name, \\localhost@SSL\..., included). Reading such a share opens
// no session to another machine. Every other server is remote, a server the
// root does not name included.
func shareOfThisMachine(root string) bool {
	_, server := windowsShareRoot(root)
	host, _, _ := strings.Cut(server, "@")
	return host != "" && actionfacts.WindowsServerIsThisMachine(host)
}
