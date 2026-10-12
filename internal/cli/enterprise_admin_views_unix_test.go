//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

type adminViewRefusalDoc struct {
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	ExitCode int `json:"exit_code"`
}

// A standard user on a standalone managed host gets the managed-view refusal
// from policy verify, as from profile-explain and sandbox list, never the
// raw config permission error (GAP-0339, GAP-0342, GAP-0349, GAP-0357). The
// fake deployment drives the managed-config pin too: on the hosts the pin
// named the config first, and the refusal then never fired.
func TestEnterprisePolicyRefusesAStandardUserLikeTheAdminViews(t *testing.T) {
	withManagedStandaloneDeployment(t, 991)
	withManagedHostCallerUID(t, 1000)
	prevJSON := enterprisePolicyJSON
	t.Cleanup(func() { enterprisePolicyJSON = prevJSON; enterprisePolicyVerifyCmd.SetOut(nil) })
	for _, asJSON := range []bool{false, true} {
		enterprisePolicyJSON = asJSON
		var out bytes.Buffer
		enterprisePolicyVerifyCmd.SetOut(&out)
		err := enterprisePolicyCmd.PersistentPreRunE(enterprisePolicyVerifyCmd, nil)
		if err == nil || !strings.Contains(err.Error(), "an administrator runs it") || !strings.Contains(err.Error(), "enterprise policy verify") ||
			strings.Contains(err.Error(), "permission denied") || commandExitCode(err) != 1 {
			t.Fatalf("json=%v: err = %v", asJSON, err)
		}
		if !asJSON {
			continue
		}
		var doc adminViewRefusalDoc
		if json.Unmarshal(out.Bytes(), &doc) != nil || len(doc.Errors) != 1 || doc.Errors[0].Code != "elevation_required" || doc.ExitCode != 1 {
			t.Fatalf("json refusal = %s", out.String())
		}
	}
}

// directoryOnlyResolver knows one directory account (a large AD uid) and its
// groups, as SSSD answers them; os/user in a static binary knows neither.
type directoryOnlyResolver struct{}

func (directoryOnlyResolver) LookupUser(string) (unixidentity.Account, error) {
	return unixidentity.Account{}, unixidentity.ErrNotFound
}
func (directoryOnlyResolver) LookupUID(uid int) (unixidentity.Account, error) {
	if uid != 94404076 {
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
	return unixidentity.Account{Name: "ent-alice@dclab.test", UID: uid, GID: 94400513}, nil
}
func (directoryOnlyResolver) LookupGroupID(gid int) (unixidentity.Group, error) {
	return map[int]unixidentity.Group{94400513: {Name: "domain users@dclab.test", GID: 94400513}, 985: {Name: "docker", GID: 985}}[gid], nil
}
func (directoryOnlyResolver) LookupGroup(string) (unixidentity.Group, error) {
	return unixidentity.Group{}, unixidentity.ErrNotFound
}
func (directoryOnlyResolver) GroupIDs(unixidentity.Account) ([]int, error) {
	return []int{94400513, 985}, nil
}
func (directoryOnlyResolver) ListUsers() ([]unixidentity.Account, bool, error) {
	return nil, false, nil
}

// The sandbox rows read an AD account's groups through the account database
// resolver, so its docker membership counts (GAP-0275).
func TestPolicyVerifyGroupsComeFromTheDirectoryResolver(t *testing.T) {
	names, err := accountGroupNamesFrom(directoryOnlyResolver{}, 94404076)
	if err != nil || !slices.Contains(names, "docker") {
		t.Fatalf("groups of a directory account = %v, %v", names, err)
	}
	if _, err := accountGroupNamesFrom(directoryOnlyResolver{}, 1); err == nil {
		t.Fatal("an unknown uid resolved")
	}
}

// profile-explain takes --json (its answer is JSON already) and refuses a
// standard user with the same JSON document (GAP-0333).
func TestProfileExplainJSONRefusesAStandardUser(t *testing.T) {
	withManagedStandaloneDeployment(t, 991)
	withManagedHostCallerUID(t, 1000)
	cmd := newEnterpriseIdentityViewCommand(unixPlatformForTest(), enterpriseIdentityViews[0])
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--user", "alice", "--connector", "codex", "--json"})
	err := cmd.Execute()
	var doc adminViewRefusalDoc
	if err == nil || json.Unmarshal(out.Bytes(), &doc) != nil || len(doc.Errors) != 1 || doc.Errors[0].Code != "elevation_required" ||
		!strings.Contains(doc.Errors[0].Message, "an administrator runs it") {
		t.Fatalf("profile-explain --json as a standard user = %v\n%s", err, out.String())
	}
}

// `enterprise linux|macos policy verify --user` is the spelling the other
// administrator views and the docs use; it is the same command, refuses the
// other OS, and a Secure Client computer drops it (GAP-0201, GAP-0240).
func TestEnterprisePolicyHasThePerOSSpelling(t *testing.T) {
	for _, platform := range []string{"linux", "macos"} {
		group := newUnixLifecycleGroup(platform, platform)
		verify, _, err := group.Find([]string{"policy", "verify"})
		if err != nil || verify.Name() != "verify" || verify.Flags().Lookup("user") == nil || verify.Flags().Lookup("json") == nil {
			t.Fatalf("%s policy verify = %v, %v", platform, verify, err)
		}
		if verify.Parent().Annotations[secureClientAbsentAnnotation] == "" {
			t.Errorf("%s policy is kept on Secure Client, which has only `enterprise policy`", platform)
		}
		if enterprisePlatformGOOS(platform) != runtime.GOOS {
			if err := verify.Parent().PersistentPreRunE(verify, nil); err == nil || commandExitCode(err) != enterprisestatus.InvalidArgsExitCode(runtime.GOOS) {
				t.Errorf("%s policy on %s = %v, want invalid arguments", platform, runtime.GOOS, err)
			}
		}
	}
	if enterprisePolicyCmd.Annotations[secureClientAbsentAnnotation] != "" {
		t.Error("`enterprise policy` itself must stay on Secure Client")
	}
}
