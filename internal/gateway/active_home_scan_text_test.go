// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// A home the path rules cannot read is spelled ~ where it is a whole path
// prefix; a home they read, a longer name and a path that merely ends in the
// home name are left as they are.
func TestActiveHomeAsTilde(t *testing.T) {
	for _, tc := range []struct{ name, text, home, want string }{
		{"dotted account", "echo x >> /home/a.b/.netrc", "/home/a.b", "echo x >> ~/.netrc"},
		{"hyphenated account", "cat /home/dc-user/.aws/credentials", "/home/dc-user/", "cat ~/.aws/credentials"},
		{"home under another root", "tee /srv/homes/ann/.npmrc", "/srv/homes/ann", "tee ~/.npmrc"},
		{"mac dotted account", "rm /Users/jo.doe/.kube/config", "/Users/jo.doe", "rm ~/.kube/config"},
		{"twice", "cp /home/a.b/x /home/a.b/.netrc", "/home/a.b", "cp ~/x ~/.netrc"},
		{"quoted", `{"p":"/home/a.b/.netrc"}`, "/home/a.b", `{"p":"~/.netrc"}`},
		{"readable home unchanged", "echo x >> /home/alice/.netrc", "/home/alice", "echo x >> /home/alice/.netrc"},
		{"root unchanged", "echo x >> /root/.netrc", "/root", "echo x >> /root/.netrc"},
		{"longer name unchanged", "echo x >> /home/a.bc/.netrc", "/home/a.b", "echo x >> /home/a.bc/.netrc"},
		{"nested path unchanged", "echo x >> /mnt/home/a.b/.netrc", "/home/a.b", "echo x >> /mnt/home/a.b/.netrc"},
		{"home itself unchanged", "ls /home/a.b", "/home/a.b", "ls /home/a.b"},
		{"no home unchanged", "echo x >> /home/a.b/.netrc", "", "echo x >> /home/a.b/.netrc"},
		{"windows home unchanged", `type C:\Users\a.b\.netrc`, `C:\Users\a.b`, `type C:\Users\a.b\.netrc`},
	} {
		if got := activeHomeAsTilde(tc.text, tc.home); got != tc.want {
			t.Errorf("%s: activeHomeAsTilde(%q, %q) = %q, want %q", tc.name, tc.text, tc.home, got, tc.want)
		}
	}
}
