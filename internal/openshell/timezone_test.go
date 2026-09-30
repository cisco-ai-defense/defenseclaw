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
	"errors"
	"testing"
)

// The host's zone is named from TZ, else /etc/localtime's link (macOS and
// Linux paths), else /etc/timezone; anything that is not a zone name is
// none (cert copilot:F10: the sandbox ran on UTC).
func TestHostTimeZone(t *testing.T) {
	noFile := errors.New("no such file")
	for _, c := range []struct {
		name, tz, link, file string
		want                 string
	}{
		{name: "macOS link", link: "/var/db/timezone/zoneinfo/America/New_York", want: "America/New_York"},
		{name: "Linux link", link: "../usr/share/zoneinfo/Europe/Berlin", want: "Europe/Berlin"},
		{name: "posix variant", link: "/usr/share/zoneinfo/posix/Asia/Kolkata", want: "Asia/Kolkata"},
		{name: "UTC", link: "/usr/share/zoneinfo/UTC", want: "UTC"},
		{name: "TZ wins", tz: "Asia/Tokyo", link: "/usr/share/zoneinfo/Europe/Berlin", want: "Asia/Tokyo"},
		{name: "TZ with a colon", tz: ":Europe/Paris", want: "Europe/Paris"},
		{name: "TZ as a path", tz: "/usr/share/zoneinfo/America/Chicago", want: "America/Chicago"},
		{name: "TZ as a POSIX rule", tz: "EST5EDT,M3.2.0,M11.1.0", link: "/usr/share/zoneinfo/Europe/Berlin", want: ""},
		{name: "a traversal", link: "/usr/share/zoneinfo/../../etc/passwd", want: ""},
		{name: "etc/timezone", file: "Australia/Sydney\n", want: "Australia/Sydney"},
		{name: "nothing", want: ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			oldLink, oldFile := localTimeLink, timezoneFile
			t.Cleanup(func() { localTimeLink, timezoneFile = oldLink, oldFile })
			localTimeLink = func() (string, error) {
				if c.link == "" {
					return "", noFile
				}
				return c.link, nil
			}
			timezoneFile = func() ([]byte, error) {
				if c.file == "" {
					return nil, noFile
				}
				return []byte(c.file), nil
			}
			if got := HostTimeZone(func(string) string { return c.tz }); got != c.want {
				t.Fatalf("HostTimeZone = %q, want %q", got, c.want)
			}
		})
	}
	for name, ok := range map[string]bool{"America/Argentina/Buenos_Aires": true, "Etc/GMT+5": true, "/etc/passwd": false, "a/../b": false, "": false, "<+03>-3": false} {
		if ValidTimeZone(name) != ok {
			t.Errorf("ValidTimeZone(%q) = %v, want %v", name, !ok, ok)
		}
	}
}
