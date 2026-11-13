// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package safetext

import (
	"strings"
	"sync/atomic"
)

// asciiOnly is UseASCII's setting.
var asciiOnly atomic.Bool

// UseASCII makes Clean, Visible, Line and every Stream show characters
// outside ASCII as '?', and Path show them as escapes. The launcher turns it
// on at start when TerminalUTF8 says the terminal does not decode UTF-8:
// such a terminal reads the bytes 0x80 to 0x9f of an ordinary character
// (U+00DD is C3 9D) as C1 controls, an 8-bit OSC among them.
func UseASCII(on bool) { asciiOnly.Store(on) }

// TerminalUTF8 reports whether the locale (LC_ALL, then LC_CTYPE, then
// LANG) lets the terminal decode UTF-8. Only a locale that names another
// character set, such as en_US.ISO-8859-1 or ja_JP.eucJP, says no. An
// unset, C or POSIX locale, or one with no character set, is taken as
// UTF-8: that is what terminals use today, and the Windows console takes
// UTF-8 from the launcher.
func TerminalUTF8(getenv func(string) string) bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := getenv(k)
		if v == "" {
			continue
		}
		_, cs, ok := strings.Cut(v, ".")
		if !ok {
			return true
		}
		cs, _, _ = strings.Cut(cs, "@")
		cs = strings.ToLower(strings.ReplaceAll(cs, "-", ""))
		return cs == "utf8"
	}
	return true
}
