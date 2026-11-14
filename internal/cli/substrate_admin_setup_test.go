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

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

const subAdminInstall = `apiVersion: install.ate.dev/v1alpha1
kind: SubstrateInstall
kindCluster:
  enabled: true
  name: substrate
images:
  repo: ghcr.io/agent-substrate
  tag: "0.10"
atenet:
  dataplane: envoy
ingressAllowedSPIFFEIDs: spiffe://cluster.local/ns/demo/sa/client
cluster:
  context: kind-substrate
  outcome: succeeded
`

// subAdminTaken has another callout in the additional slot (D10).
var subAdminTaken = strings.Replace(subAdminInstall, "  dataplane: envoy\n",
	"  dataplane: envoy\n  egress:\n    additionalExtprocService: other-system/other-callout:9000\n", 1)

const subAdminOverlayDir = "../substrate/setup/testdata/overlay"

func subAdminWrite(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func subAdminRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func subAdminExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestSubstrate_Admin_SetupWritesNextToTheFile(t *testing.T) {
	dir := t.TempDir()
	file := subAdminWrite(t, dir, "install.yaml", subAdminInstall)
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--namespace", "defenseclaw-system")
	if err != nil {
		t.Fatal(err)
	}
	if got := subAdminRead(t, file); got != subAdminInstall {
		t.Errorf("the install file changed without --yes:\n%s", got)
	}
	want, report, err := setup.RenderOverlay([]byte(subAdminInstall), setup.OverlayOptions{Namespace: "defenseclaw-system", CalloutPort: 9443})
	if err != nil {
		t.Fatal(err)
	}
	if got := subAdminRead(t, file+".new"); got != string(want) {
		t.Errorf("the new document differs from the overlay:\n%s", got)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(file + ".new"); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("mode of the new file: %v %v", st, err)
		}
	}
	if len(report.Changes) < 2 {
		t.Fatalf("overlay changes: %+v", report.Changes)
	}
	for _, w := range []string{
		"set atenet.egress.additionalExtprocService to defenseclaw-system/defenseclaw-callout:9443",
		"changed ingressAllowedSPIFFEIDs from spiffe://cluster.local/ns/demo/sa/client to ",
		"Wrote " + file + ".new", "mode 0600",
		"Next: run ate-setup deploy --config " + file + ".new", "helm install",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	if subAdminExists(file + ".bak") {
		t.Error("a backup was made without --yes")
	}
}

func TestSubstrate_Admin_SetupGoldens(t *testing.T) {
	fakeKubectl(t, errors.New("kubectl is not installed or not on PATH"))
	cases := []struct {
		name   string
		golden string
		args   []string
	}{
		{"stock v1.0.0", "new-v1.0.0.yaml", []string{"--namespace", "defenseclaw-system"}},
		{"all capabilities", "new-all-capabilities.yaml", []string{"--namespace", "defenseclaw-system", "--capability", "body-mode", "--capability", "route-timeouts", "--issuer", "https://idp.cluster-a.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "install.yaml")
			out, _, err := runSubAdmin(newSubstrateSetupCmd(), append([]string{"--install-file", file, "--yes"}, tc.args...)...)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(subAdminOverlayDir, tc.golden))
			if err != nil {
				t.Fatal(err)
			}
			want = []byte(strings.ReplaceAll(string(want), "\r\n", "\n"))
			if got := subAdminRead(t, file); got != string(want) {
				t.Errorf("document differs from %s:\n%s", tc.golden, got)
			}
			if !strings.Contains(out, "does not exist; starting a new SubstrateInstall document") {
				t.Errorf("a new file is not said to be new:\n%s", out)
			}
			if subAdminExists(file+".bak") || subAdminExists(file+".new") {
				t.Error("a new file left a .bak or .new")
			}
		})
	}
}

func TestSubstrate_Admin_SetupYesReplacesAndKeepsBackup(t *testing.T) {
	dir := t.TempDir()
	file := subAdminWrite(t, dir, "install.yaml", subAdminInstall)
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if got := subAdminRead(t, file+".bak"); got != subAdminInstall {
		t.Errorf("the backup is not the original:\n%s", got)
	}
	if !strings.Contains(subAdminRead(t, file), "defenseclaw-callout:9443") {
		t.Error("the file was not replaced")
	}
	if subAdminExists(file + ".new") {
		t.Error("--yes also left a .new")
	}
	if !strings.Contains(out, "the old file is kept as "+file+".bak") {
		t.Errorf("output:\n%s", out)
	}

	// A second run finds nothing to do and writes nothing.
	os.Remove(file + ".bak")
	out, _, err = runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Nothing to change") || subAdminExists(file+".bak") || subAdminExists(file+".new") {
		t.Errorf("a second run wrote something:\n%s", out)
	}
	if strings.Contains(out, "Next:") {
		t.Errorf("a second run tells what to run next:\n%s", out)
	}
}

func TestSubstrate_Admin_SetupDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	file := subAdminWrite(t, dir, "install.yaml", subAdminInstall)
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--dry-run", "--yes", "--capability", "route-timeouts")
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || subAdminRead(t, file) != subAdminInstall {
		t.Errorf("a dry run changed the folder: %v", entries)
	}
	for _, w := range []string{"Dry run: nothing was written", "set atenet.router.routeTimeout to 4h"} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

func TestSubstrate_Admin_SetupRefusals(t *testing.T) {
	cases := []struct {
		name    string
		install string
		args    []string
		exit    int
		want    []string
	}{
		{
			name:    "another callout holds the slot",
			install: subAdminTaken,
			exit:    substrateExitRefused,
			want:    []string{"not changed", "another callout", "Remove it from the SubstrateInstall document", "substrate.extproc.enabled: false"},
		},
		{
			name:    "OpenAPPA holds the slot",
			install: subAdminInstall + "openappa:\n  enabled: true\n",
			exit:    substrateExitRefused,
			want:    []string{"not changed", "OpenAPPA"},
		},
		{
			name:    "another dataplane",
			install: strings.Replace(subAdminInstall, "dataplane: envoy", "dataplane: cilium", 1),
			exit:    substrateExitRefused,
			want:    []string{"not changed", "dataplane: envoy"},
		},
		{
			name:    "unknown capability",
			install: subAdminInstall,
			args:    []string{"--capability", "warp-drive"},
			exit:    2,
			want:    []string{"warp-drive", "body-mode", "route-timeouts"},
		},
		{
			name:    "not a SubstrateInstall document",
			install: "apiVersion: v1\nkind: ConfigMap\n",
			exit:    2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			install := tc.install
			file := subAdminWrite(t, dir, "install.yaml", install)
			_, _, err := runSubAdmin(newSubstrateSetupCmd(), append([]string{"--install-file", file, "--yes"}, tc.args...)...)
			if err == nil || commandExitCode(err) != tc.exit {
				t.Fatalf("err %v (exit %d), want exit %d", err, commandExitCode(err), tc.exit)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the error lacks %q: %v", w, err)
				}
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 1 || subAdminRead(t, file) != install {
				t.Errorf("a refused setup changed the folder: %v", entries)
			}
		})
	}
}

func TestSubstrate_Admin_SetupRemove(t *testing.T) {
	dir := t.TempDir()
	file := subAdminWrite(t, dir, "install.yaml", subAdminInstall)
	if _, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--yes", "--capability", "route-timeouts"); err != nil {
		t.Fatal(err)
	}
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--remove", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	got := subAdminRead(t, file)
	if strings.Contains(got, "defenseclaw-callout") || strings.Contains(got, "defenseclaw-gateway") {
		t.Errorf("DefenseClaw's settings are still in the file:\n%s", got)
	}
	if !strings.Contains(got, "spiffe://cluster.local/ns/demo/sa/client") {
		t.Errorf("another router client was removed:\n%s", got)
	}
	for _, w := range []string{"removed atenet.egress.additionalExtprocService", "atenet.router.routeTimeout stays", "helm uninstall"} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	out, _, err = runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--remove", "--dry-run")
	if err != nil || !strings.Contains(out, "Nothing to remove") {
		t.Errorf("%v\n%s", err, out)
	}
	_, _, err = runSubAdmin(newSubstrateSetupCmd(), "--install-file", filepath.Join(dir, "none.yaml"), "--remove")
	if err == nil || commandExitCode(err) != 2 || !strings.Contains(err.Error(), "nothing to remove") {
		t.Errorf("remove of a missing file: %v (exit %d)", err, commandExitCode(err))
	}
}

func TestSubstrate_Admin_SetupJSON(t *testing.T) {
	dir := t.TempDir()
	file := subAdminWrite(t, dir, "install.yaml", subAdminInstall)
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var res substrateSetupResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if res.Action != "setup" || res.Written != file+".new" || len(res.Changes) < 2 || res.DryRun {
		t.Errorf("result: %+v", res)
	}
}

func TestSubstrate_Admin_SetupNeedsAFile(t *testing.T) {
	_, _, err := runSubAdmin(newSubstrateSetupCmd())
	if err == nil || commandExitCode(err) != 2 || !strings.Contains(err.Error(), "--install-file") {
		t.Fatalf("err %v (exit %d)", err, commandExitCode(err))
	}
}

func TestSubstrate_Admin_SetupPrintAccessPolicies(t *testing.T) {
	plan := setup.ChartPlan{
		Schema: setup.PlanSchema, Release: "dc", Namespace: "defenseclaw-system", ChartVersion: "1.0.10", AppVersion: "1.0.10",
		StoreSchema: 1, SubstrateNamespace: "ate-system", SupportedVersions: ">=1.0.0 <1.1.0",
		API:               setup.PlanAPI{Address: "api.ate-system.svc:443", Audience: "api.ate-system.svc"},
		ActorHost:         "defenseclaw-actor.defenseclaw-system.svc",
		LauncherAtespaces: []string{"eng-web"},
		WritableAtespaces: []string{"data-team", "eng-web"},
		Editors:           []string{"system:serviceaccount:defenseclaw-system:defenseclaw-gateway"},
		GlobalViewers:     []string{"system:serviceaccount:defenseclaw-system:defenseclaw-gateway"},
		CredentialProvider: setup.CredentialProvider{Grant: true, ConfigMap: "k8s-credential-provider-namespace-policy",
			Deployment: "k8s-credential-provider", SecretsNamespace: "defenseclaw-actor-secrets"},
		StoreStateConfigMap: "defenseclaw-store-state",
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	planFile := subAdminWrite(t, t.TempDir(), "plan.json", string(raw))
	want, err := setup.PrintAccessPolicies(plan)
	if err != nil {
		t.Fatal(err)
	}

	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--print-access-policies", "--plan", planFile)
	if err != nil {
		t.Fatal(err)
	}
	if out != want || !strings.Contains(out, "Launcher atespace eng-web") {
		t.Errorf("printed policies differ:\n%s", out)
	}

	out, _, err = runSubAdmin(newSubstrateSetupCmd(), "--print-access-policies", "--plan", planFile, "--json")
	var res substrateSetupResult
	if err != nil || json.Unmarshal([]byte(out), &res) != nil || res.AccessPolicies != want || res.Action != "print-access-policies" {
		t.Errorf("json: %v\n%s", err, out)
	}

	if _, _, err = runSubAdmin(newSubstrateSetupCmd(), "--print-access-policies"); err == nil || commandExitCode(err) != 2 {
		t.Errorf("no --plan: %v (exit %d)", err, commandExitCode(err))
	}
	if _, _, err = runSubAdmin(newSubstrateSetupCmd(), "--print-access-policies", "--plan", filepath.Join(t.TempDir(), "none.json")); err == nil || commandExitCode(err) != 2 {
		t.Errorf("missing plan: %v (exit %d)", err, commandExitCode(err))
	}
}
