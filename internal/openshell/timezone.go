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

package openshell

import (
	"os"
	"regexp"
	"strings"
)

// EnvHostTimeZone carries this machine's IANA time zone into a sandbox
// (registered in internal/envvars/registry.json). A sandbox otherwise runs
// on UTC; the in-image shell fragment (harness.TimeZoneScript) exports TZ
// from it when the image has that zone's file and TZ is not set already.
const EnvHostTimeZone = "DEFENSECLAW_HOST_TZ"

// timeZonePattern is an IANA zone name ("America/New_York", "UTC",
// "Etc/GMT+5"): letters first, then letters, digits, _, + and -, in at most
// four parts. It rules out a path, a "..", and POSIX TZ strings with angle
// brackets or commas.
var timeZonePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,3}$`)

// ValidTimeZone reports whether name is an IANA zone name a sandbox may be
// given.
func ValidTimeZone(name string) bool {
	return len(name) <= 64 && timeZonePattern.MatchString(name)
}

// localTimeLink and timezoneFile are the system files HostTimeZone reads
// (tests replace them).
var (
	localTimeLink = func() (string, error) { return os.Readlink("/etc/localtime") }
	timezoneFile  = func() ([]byte, error) { return os.ReadFile("/etc/timezone") }
)

// HostTimeZone is this machine's IANA time zone, or "" when it cannot be
// named: TZ (":Europe/Berlin", a zoneinfo path, or a zone name), else the
// zone /etc/localtime links to (/var/db/timezone/zoneinfo/America/New_York
// on macOS, /usr/share/zoneinfo/... on Linux), else /etc/timezone (Debian).
func HostTimeZone(getenv func(string) string) string {
	if getenv != nil {
		if tz := strings.TrimSpace(getenv("TZ")); tz != "" {
			return zoneName(strings.TrimPrefix(tz, ":"))
		}
	}
	if link, err := localTimeLink(); err == nil {
		if zone := zoneName(link); zone != "" {
			return zone
		}
	}
	if data, err := timezoneFile(); err == nil {
		return zoneName(strings.TrimSpace(string(data)))
	}
	return ""
}

// zoneName is the IANA name in s, a zone name or a path under a zoneinfo
// directory (its posix/ or right/ variants included), or "".
func zoneName(s string) string {
	if i := strings.LastIndex(s, "zoneinfo/"); i >= 0 {
		s = s[i+len("zoneinfo/"):]
		for _, variant := range []string{"posix/", "right/"} {
			s = strings.TrimPrefix(s, variant)
		}
	}
	if !ValidTimeZone(s) {
		return ""
	}
	return s
}
