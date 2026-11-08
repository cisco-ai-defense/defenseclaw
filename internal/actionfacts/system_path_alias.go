// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"runtime"
	"strings"
)

// HostLinksEtcToPrivate reports whether this host links /etc to /private/etc
// (macOS). Only there is /private/etc another spelling of /etc; on any other
// host /private/etc is an ordinary directory and its files are ordinary
// files. Tests that exercise the macOS spelling on another host set it.
var HostLinksEtcToPrivate = runtime.GOOS == "darwin"

// EtcSpelling returns value with the physical macOS spelling of /etc
// (/private/etc, where /etc is a link) written as /etc. Every exact proof
// that names a system file under /etc accepts a call that names the same
// file by its physical spelling, so the protected content rules decide a
// direct /private/etc operand the way they decide /etc (GAP-0819). Any other
// path, and every path on a host where /etc is not a link, is returned
// unchanged.
func EtcSpelling(value string) string {
	if HostLinksEtcToPrivate && (value == "/private/etc" || strings.HasPrefix(value, "/private/etc/")) {
		return strings.TrimPrefix(value, "/private")
	}
	return value
}
