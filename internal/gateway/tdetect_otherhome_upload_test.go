// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestOtherHomeCredentialFileUploadFiveTiers (rel-1-0-10:GAP-0835): the
// /inspect/tool exec route judges an external upload of another account's
// credentials file as the hook route does (rel blocked the AWS, netrc and git
// uploads CRITICAL there; the docker config upload fell to a clean allow), and
// no tier but permissive lets it through without an alert.
func TestOtherHomeCredentialFileUploadFiveTiers(t *testing.T) {
	td810OtherHomeFiles(t, func(pack string, hook, inspect func(id, command string) any, file, home string) {
		path := home + "/" + file
		hookUpload := hook("up-"+path, td810UploadCommand(path))
		if got := inspect("", td810UploadCommand(path)); got != hookUpload {
			t.Errorf("%s: /inspect/tool upload of %s is %v, the hook route answers %v", pack, path, got, hookUpload)
		}
		if pack != "permissive" && td810Rank(hookUpload) < 1 {
			t.Errorf("%s: hook upload of %s is %v, want at least an alert", pack, path, hookUpload)
		}
	})
}
