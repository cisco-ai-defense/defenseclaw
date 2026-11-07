// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// EtcSpelling returns value with the physical macOS spelling of /etc
// (/private/etc, where /etc is a link) written as /etc. Every exact proof
// that names a system file under /etc accepts a call that names the same
// file by its physical spelling, so the protected content rules decide a
// direct /private/etc operand the way they decide /etc (GAP-0819). Any other
// path is returned unchanged.
func EtcSpelling(value string) string {
	if value == "/private/etc" || strings.HasPrefix(value, "/private/etc/") {
		return strings.TrimPrefix(value, "/private")
	}
	return value
}
