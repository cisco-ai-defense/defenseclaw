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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// GAP-0460: the GitOps path. --overlay-only (alias --no-chart) writes the
// same overlay as plain setup, runs the same checks, never mentions helm, and
// names the chart values the overlay assumes.

func TestSubstrate_Admin_SetupOverlayOnlyWritesTheSameOverlay(t *testing.T) {
	dir := t.TempDir()
	plain := subAdminWrite(t, dir, "plain.yaml", subAdminInstall)
	gitops := subAdminWrite(t, dir, "gitops.yaml", subAdminInstall)
	if _, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", plain, "--yes"); err != nil {
		t.Fatal(err)
	}
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", gitops, "--overlay-only", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if subAdminRead(t, gitops) != subAdminRead(t, plain) {
		t.Errorf("--overlay-only wrote a different document:\n%s\nvs\n%s", subAdminRead(t, gitops), subAdminRead(t, plain))
	}
	if strings.Contains(out, "helm") {
		t.Errorf("the GitOps path names helm:\n%s", out)
	}
	for _, w := range []string{
		"Next: commit " + gitops + " and run ate-setup deploy --config " + gitops,
		"Argo CD or Flux installs the chart",
		"callout.port: 9443",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

func TestSubstrate_Admin_SetupNoChartIsTheSameSwitch(t *testing.T) {
	dir := t.TempDir()
	file := subAdminWrite(t, dir, "install.yaml", subAdminInstall)
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--no-chart", "--issuer", "https://a.example", "--dry-run", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var res substrateSetupResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if res.Mode != "overlay-only" || res.ChartValues["callout.port"] != "9443" ||
		res.ChartValues["config.substrate.identity.issuer"] != "https://a.example" || !res.DryRun || res.Written != "" {
		t.Errorf("result: %+v", res)
	}
}

func TestSubstrate_Admin_SetupPlainJSONKeepsItsShape(t *testing.T) {
	dir := t.TempDir()
	file := subAdminWrite(t, dir, "install.yaml", subAdminInstall)
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--dry-run", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"mode"`) || strings.Contains(out, "chart_values") {
		t.Errorf("plain setup carries the GitOps fields:\n%s", out)
	}
}

// The checks never weaken: another callout still refuses, and nothing is written.
func TestSubstrate_Admin_SetupOverlayOnlyKeepsEveryRefusal(t *testing.T) {
	dir := t.TempDir()
	file := subAdminWrite(t, dir, "install.yaml", subAdminTaken)
	_, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--overlay-only", "--yes")
	if err == nil || cliusage.ExitCode(err) != substrateExitRefused || !strings.Contains(err.Error(), "another callout") {
		t.Fatalf("err %v (exit %d)", err, cliusage.ExitCode(err))
	}
	if got := subAdminRead(t, file); got != subAdminTaken || subAdminExists(file+".new") || subAdminExists(file+".bak") {
		t.Errorf("the refusal wrote something:\n%s", got)
	}
}

func TestSubstrate_Admin_SetupOverlayOnlyRemove(t *testing.T) {
	dir := t.TempDir()
	file := subAdminWrite(t, dir, "install.yaml", subAdminInstall)
	if _, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--yes"); err != nil {
		t.Fatal(err)
	}
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--overlay-only", "--remove", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "helm") || strings.Contains(out, "chart_values") || strings.Contains(out, "callout.port") ||
		!strings.Contains(out, "remove the chart from the repo Argo CD or Flux reads") {
		t.Errorf("remove output:\n%s", out)
	}
}

func TestSubstrate_Admin_SetupOverlayOnlyRefusesAccessPolicies(t *testing.T) {
	_, _, err := runSubAdmin(newSubstrateSetupCmd(), "--overlay-only", "--print-access-policies", "--plan", "x.json")
	if err == nil || cliusage.ExitCode(err) != 2 || !strings.Contains(err.Error(), "--overlay-only") {
		t.Fatalf("err %v (exit %d)", err, cliusage.ExitCode(err))
	}
}
