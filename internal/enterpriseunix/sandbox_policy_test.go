// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// sandboxProfilesConfig is DefaultConfig with a contractors floor stricter
// than the default profile's, and a request_access contact.
func sandboxProfilesConfig(h *testHost) string {
	return strings.Replace(string(DefaultConfig(h.env.Layout)), "  rule_pack: default\n", `  rule_pack: default
  profiles:
    contractors:
      mode: action
      sandbox: {required_for: [claudecode], allow_unblock: false, user_approvals: session}
    offline-floor:
      mode: action
      sandbox: {allow_mount: false}
  profile_assignments:
    - profile: contractors
      match: {groups: ["contractors@corp.example.com"]}
  default_profile: offline-floor
openshell:
  admin:
    request_access: it-security@example.invalid
`, 1)
}

// GAP-0188, GAP-0331, GAP-0393: ensure, status and verify name, field by
// field, where default_profile is looser than an assigned profile, and the
// advisories; the same list on a rerun, and never as an error.
func TestDescribeSandboxPolicyWarnsFieldByField(t *testing.T) {
	h := newTestHost(t, "linux")
	writeHostFile(t, h, h.env.Layout.ConfigPath, sandboxProfilesConfig(h))
	describe := func() string {
		l := &lifecycle{env: h.env, result: &enterprisestatus.Result{}}
		l.describeSandboxPolicy(context.Background())
		if len(l.result.Errors) != 0 {
			t.Fatalf("errors = %+v", l.result.Errors)
		}
		return messagesOf(l.result.Warnings, enterprisestatus.CodeSandboxDefaultProfile)
	}
	got := describe()
	for _, want := range []string{
		"default_profile lacks required_for [claudecode] from contractors",
		"default_profile lacks allow_unblock false from contractors",
		"default_profile lacks user_approvals session from contractors",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if again := describe(); again != got {
		t.Fatalf("a rerun lists other warnings:\n%s\n---\n%s", got, again)
	}
}

// GAP-0380, GAP-0403: a sandbox packs folder other accounts can read is
// refused by every ensure, the config unchanged included, and fails verify;
// root:<service group> 0750 passes. The fix never opens it to others.
func TestEnsureRefusesASandboxPacksFolderOthersCanRead(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	account := h.accounts.accounts[h.env.Layout.ServiceUser]
	dir := filepath.Join(h.env.Layout.VendorPolicyDir, "sandbox")
	if err := os.MkdirAll(h.env.P(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.env.P(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	h.owners[h.env.P(dir)] = [2]int{0, account.GID}

	r := h.run(Options{Action: ActionEnsure})
	requireError(t, r, codeConfig)
	got := messagesOf(r.Errors, codeConfig)
	if !strings.Contains(got, dir+" is 0755, so every account can read") ||
		!strings.Contains(got, "root:"+h.env.Layout.ServiceGroup+" with mode 0750") || strings.Contains(got, "o+") {
		t.Fatalf("errors = %s", got)
	}
	r = h.run(Options{Action: ActionVerify})
	if r.OK || !strings.Contains(messagesOf(r.Errors, codeVerify), "every account can read") {
		t.Fatalf("verify passed a world-readable packs folder: %+v", r.Errors)
	}

	if err := os.Chmod(h.env.P(dir), 0o750); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	// A group other than root's or the service account's could read it too.
	h.owners[h.env.P(dir)] = [2]int{0, account.GID + 7}
	if problem := h.env.sandboxPackDirProblem(context.Background(), &config.Config{PolicyDir: h.env.Layout.VendorPolicyDir}); !strings.Contains(problem, "owned by uid 0 gid") {
		t.Fatalf("problem = %q", problem)
	}
}

// GAP-0501: packs staged before the first install (when the service group
// does not exist yet) get the service group from the install; GAP-0521: on
// an installed host a pack the service account cannot read is refused before
// activation, with the cause and the service-group fix.
func TestStagedSandboxPacksGetTheServiceGroup(t *testing.T) {
	h := newTestHost(t, "linux")
	dir := filepath.Join(h.env.Layout.VendorPolicyDir, "sandbox")
	strict := filepath.Join(dir, "strict")
	if err := os.MkdirAll(h.env.P(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	for parent := filepath.Dir(dir); parent != "/"; parent = filepath.Dir(parent) {
		if err := os.Chmod(h.env.P(parent), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, mode := range map[string]os.FileMode{dir: 0o755, strict: 0o750} {
		if err := os.MkdirAll(h.env.P(path), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(h.env.P(path), mode); err != nil {
			t.Fatal(err)
		}
	}
	pack := filepath.Join(strict, "pack.yaml")
	writeHostFile(t, h, pack, "name: strict\n")
	if err := os.Chmod(h.env.P(pack), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, strict, pack} {
		h.owners[h.env.P(path)] = [2]int{0, 0}
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireOK(t, r)
	account := h.accounts.accounts[h.env.Layout.ServiceUser]
	for path, want := range map[string]os.FileMode{dir: 0o750, strict: 0o750, pack: 0o640} {
		uid, gid, _ := h.env.OwnerOf(h.env.P(path))
		if got := h.mode(path); got != want || uid != 0 || gid != account.GID {
			t.Errorf("%s is %04o %d:%d, want %04o 0:%d", path, got, uid, gid, want, account.GID)
		}
	}
	if !containsLine(r.Changes, "gave the "+h.env.Layout.ServiceGroup+" service group read access to the sandbox packs staged in "+dir) {
		t.Errorf("changes = %v", r.Changes)
	}

	// Installed: a new pack the service account cannot read is refused, not
	// re-owned.
	own := filepath.Join(dir, "own")
	if err := os.MkdirAll(h.env.P(own), 0o750); err != nil {
		t.Fatal(err)
	}
	h.owners[h.env.P(own)] = [2]int{0, 0}
	r = h.run(Options{Action: ActionEnsure})
	requireError(t, r, codeConfig)
	got := messagesOf(r.Errors, codeConfig)
	if !strings.Contains(got, own+" is 0750 owned by uid 0 gid 0, so the "+h.env.Layout.ServiceUser+" gateway service account cannot read the sandbox pack") ||
		!strings.Contains(got, "root:"+h.env.Layout.ServiceGroup) || strings.Contains(got, "outside") {
		t.Fatalf("errors = %s", got)
	}
	if _, gid, _ := h.env.OwnerOf(h.env.P(own)); gid != 0 {
		t.Error("ensure re-owned a pack on an installed host")
	}
}

// GAP-0258: a policy folder the service account cannot pass through is
// fixed through the service group, never by opening it to other accounts.
func TestRulePackTraversalAdviceNamesTheServiceGroup(t *testing.T) {
	h := newTestHost(t, "linux")
	if _, err := h.env.Accounts.Ensure(context.Background(), h.env.Layout.ServiceUser); err != nil {
		t.Fatal(err)
	}
	const parent = "/etc/defenseclaw/policies/guardrail"
	dir := parent + "/custom"
	if err := os.MkdirAll(h.env.P(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.env.P(parent), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(h.env.P(parent), 0o755) })
	got := h.env.RulePackServiceReadProblem(context.Background(), dir)
	group := h.env.Layout.ServiceGroup
	if !strings.Contains(got, "cannot reach the rule pack") || !strings.Contains(got, "chown root:"+group+" "+parent+" && chmod 0750 "+parent) ||
		strings.Contains(got, "o+x") {
		t.Fatalf("problem = %q", got)
	}
	if err := os.Chmod(h.env.P(parent), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.env.P(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	got = h.env.RulePackServiceReadProblem(context.Background(), dir)
	if !strings.Contains(got, "chown -R root:"+group+" "+dir+" && chmod -R u=rwX,g=rX "+dir) || strings.Contains(got, "go=rX") {
		t.Fatalf("problem = %q", got)
	}
}
