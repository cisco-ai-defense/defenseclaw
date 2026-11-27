// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import "testing"

// GAP-0636: the gateway guessed the programs a fetched npm package declares
// (name, base, mcp-<base>, <scope>-<base>, mcp-server-<scope>), so a
// node_modules/.bin entry of the project with a declared name outside the
// guess stood in for the server unseen. The kit now reports the declared
// bins of the packages in the actor's npx cache (role mcp_fetch_bins); they
// add to the guess and never replace it. The role is spelled out so the
// rows build at a parent without the constant.
func TestGAP0636DeclaredBinsFromNpxCache(t *testing.T) {
	const role = "mcp_fetch_bins"
	checked := AttachedFile{Role: RoleFetchChecked, Path: "/work/repo"}
	names := func(s string) AttachedFile {
		return AttachedFile{Role: RoleFetchNames, Path: "/work/repo/node_modules", Content: []byte(s)}
	}
	bins := func(s string) AttachedFile {
		return AttachedFile{Role: role, Path: "/home/u/.npm/_npx", Content: []byte(s)}
	}
	acme := []string{"-y", "@acme/tools@1.4.0"}
	type row struct {
		args  []string
		files []AttachedFile
	}
	unknown := map[string]row{
		"a declared program outside the guess": {acme, []AttachedFile{checked, names("left-pad\n.bin/acme-run"), bins("@acme/tools\tacme-run")}},
		"the declared program as a shim":       {acme, []AttachedFile{checked, names(".bin/Acme-Run.cmd"), bins("@acme/tools\tacme-run")}},
		"an unscoped package's second program": {[]string{"-y", "some-mcp"}, []AttachedFile{checked, names(".bin/srv-x"), bins("some-mcp\tsome-mcp\nsome-mcp\tsrv-x")}},
		"two cached versions, union":           {[]string{"-y", "some-mcp@2"}, []AttachedFile{checked, names(".bin/b-tool"), bins("some-mcp\ta-tool"), bins("some-mcp\tb-tool")}},
		"the --package package's other bin":    {[]string{"-y", "--package=@acme/tools", "acme-main"}, []AttachedFile{checked, names(".bin/acme-helper"), bins("@acme/tools\tacme-main\n@acme/tools\tacme-helper")}},
		"a cut list keeps the lines it has":    {acme, []AttachedFile{checked, names(".bin/acme-run"), {Role: role, Path: "/home/u/.npm/_npx", Content: []byte("@acme/tools\tacme-run"), Truncated: true}}},
		"the guess still holds beside it":      {acme, []AttachedFile{checked, names(".bin/acme-tools"), bins("@acme/tools\tacme-run")}},
	}
	for name, r := range unknown {
		if d := repoServerDecision(t, "npx", r.args, nil, r.files...); !d.Unavailable {
			t.Errorf("%s: %+v, want unscanned (the fail mode decides)", name, d)
		}
	}
	known := map[string]row{
		"another package's program":         {acme, []AttachedFile{checked, names(".bin/acme-run"), bins("other-pkg\tacme-run")}},
		"the vendor's own CLI (GAP-0573)":   {[]string{"-y", "@playwright/mcp@latest"}, []AttachedFile{checked, names("@playwright/test\n.bin/playwright"), bins("@playwright/mcp\tmcp-server-playwright")}},
		"the project's own tools":           {acme, []AttachedFile{checked, names(".bin/tsc\n.bin/eslint"), bins("@acme/tools\tacme-run")}},
		"an empty or cut list":              {acme, []AttachedFile{checked, names(".bin/acme-run"), {Role: role, Path: "/home/u/.npm/_npx", Truncated: true}}},
		"lines the gateway does not read":   {acme, []AttachedFile{checked, names(".bin/acme-run"), bins("@acme/tools acme-run\n\tacme-run\n@acme/tools\t")}},
		"no npx cache (first run, old kit)": {acme, []AttachedFile{checked, names(".bin/acme-run")}},
	}
	for name, r := range known {
		if d := repoServerDecision(t, "npx", r.args, nil, r.files...); d.Unavailable {
			t.Errorf("%s: %+v, want decided by the config rules", name, d)
		}
	}
}
