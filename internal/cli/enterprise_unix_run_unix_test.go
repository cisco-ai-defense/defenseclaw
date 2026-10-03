// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A standard account running `enterprise secret status` on a managed host
// got the raw "open /etc/defenseclaw/secrets: permission denied".
func TestEnterpriseSecretStatusAsStandardUserNamesAdministratorRights(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a 0000 directory")
	}
	goos := enterpriseunix.CurrentGOOS()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	secrets := root + layout.SecretsDir
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secrets, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secrets, 0o700) })
	previous := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 1000 }}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })

	cmd := newEnterpriseSecretCommand("status", "")
	var out bytes.Buffer
	cmd.SetOut(&out)
	err = runEnterpriseSecret(cmd, "status", &enterpriseSecretOptions{})
	if err == nil {
		t.Fatal("secret status succeeded without access to the credentials directory")
	}
	if strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "administrator rights") ||
		!strings.Contains(err.Error(), "sudo "+layout.BinDir+"/defenseclaw-gateway enterprise secret status") {
		t.Fatalf("secret status error = %q", err)
	}
	if commandExitCode(err) != 1 {
		t.Fatalf("exit code %d", commandExitCode(err))
	}
}

// verify printed every failed target three times: as a "! <code>" warning,
// as a "✗ verify_failed" error and again in the final "Error: verify
// failed: ..." line. Each problem is printed once, with its specific code,
// and the headline of a result with warnings is not a green check.
func TestLifecycleOutputPrintsEachProblemOnce(t *testing.T) {
	target := "devin 3000.11.3 for user alice has no verified DefenseClaw hook contract, so it runs without DefenseClaw hooks"
	other := "com.cisco.defenseclaw.hook-enumerator is not active"
	result := enterprisestatus.New("verify", "standalone", "darwin", "1.0.0")
	result.AddWarning("hook_contract_unverified", target)
	result.AddError("verify_failed", other)
	result.AddError("verify_failed", target)
	result.Finish("darwin", 0)
	var out bytes.Buffer
	if err := printLifecycleResult(&out, result, false); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.Count(text, target) != 1 || strings.Count(text, other) != 1 {
		t.Fatalf("each problem must be printed once:\n%s", text)
	}
	if !strings.Contains(text, "✗ hook_contract_unverified: "+target) {
		t.Fatalf("the problem lost its specific code:\n%s", text)
	}

	// The error line after the listing does not repeat the problems.
	previous := newUnixLifecycleEnv
	root := t.TempDir()
	goos := enterpriseunix.CurrentGOOS()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Skip(err)
	}
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 0 }}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })
	platform := "linux"
	if goos == "darwin" {
		platform = "macos"
	}
	cmd := &cobra.Command{}
	out.Reset()
	cmd.SetOut(&out)
	runErr := runUnixLifecycle(cmd, platform, "verify", &unixLifecycleOptions{})
	if runErr == nil {
		t.Fatal("verify of an empty host succeeded")
	}
	listed := 0
	for _, line := range strings.Split(out.String(), "\n") {
		message, ok := strings.CutPrefix(line, "  ✗ ")
		if !ok {
			continue
		}
		listed++
		if _, text, found := strings.Cut(message, ": "); found && strings.Contains(runErr.Error(), text) {
			t.Fatalf("the error line repeats a listed problem: %q", runErr)
		}
	}
	if listed == 0 {
		t.Fatalf("verify listed no problem:\n%s", out.String())
	}

	ok := enterprisestatus.New("status", "standalone", "linux", "1.0.0")
	ok.AddWarning("unit_failed", "defenseclaw-enterprise-apply.service failed")
	ok.Inspection.Local, ok.Inspection.AIDefense = "active", "unavailable:auth_failed"
	ok.Finish("linux", 0)
	out.Reset()
	if err := printLifecycleResult(&out, ok, false); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(out.String(), "✓") {
		t.Fatalf("a result with warnings got a green check:\n%s", out.String())
	}
	// Human status names the AI Defense state, not only the JSON.
	if !strings.Contains(out.String(), "inspection: local=active ai_defense=unavailable:auth_failed") {
		t.Fatalf("status hides the inspection state:\n%s", out.String())
	}
}

// A failed verify of an installed deployment ends with the repair command
// (GAP-1094); other failures and --json keep their line.
func TestLifecycleFailureOfAnInstalledVerifyNamesRepair(t *testing.T) {
	const repair = "/usr/bin/defenseclaw-gateway enterprise linux repair"
	result := enterprisestatus.New(enterpriseunix.ActionVerify, "standalone", "linux", "1.0.0")
	result.Installed = true
	result.AddError("verify_failed", "defenseclaw-sensor-helper.service is not active")
	result.AddError("verify_failed", "DefenseClaw hooks are not in place in vendor machine policy for claudecode")
	result.Finish("linux", 0)
	err := lifecycleFailure(result, false, repair)
	if want := "verify failed; see the 2 problems listed above. Run `" + repair + "` as root to fix them"; err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if commandExitCode(err) != result.ExitCode {
		t.Fatalf("exit code %d, want %d", commandExitCode(err), result.ExitCode)
	}
	if err := lifecycleFailure(result, true, repair); strings.Contains(err.Error(), "repair") {
		t.Fatalf("--json error line = %q, want the problems only", err)
	}
	// One problem reads "fix it" (GAP-1435).
	single := enterprisestatus.New(enterpriseunix.ActionVerify, "standalone", "linux", "1.0.0")
	single.Installed = true
	single.AddError("verify_failed", "defenseclaw-sensor-helper.service is not active")
	single.Finish("linux", 0)
	if want := "verify failed; see the 1 problem listed above. Run `" + repair + "` as root to fix it"; lifecycleFailure(single, false, repair).Error() != want {
		t.Fatalf("one problem: %q, want %q", lifecycleFailure(single, false, repair), want)
	}
	result.Installed = false
	if err := lifecycleFailure(result, false, repair); strings.Contains(err.Error(), "repair") {
		t.Fatalf("not installed: %q, want no repair advice", err)
	}
	// GAP-2246: a status that found another run in progress checked nothing.
	busy := enterprisestatus.New(enterpriseunix.ActionStatus, "standalone", "darwin", "1.0.0")
	busy.Installed = true
	busy.AddError("lifecycle_busy", "another DefenseClaw enterprise lifecycle run is in progress")
	busy.Finish("darwin", enterprisestatus.UnixExitBusy)
	if err := lifecycleFailure(busy, false, repair); strings.Contains(err.Error(), "repair") {
		t.Fatalf("busy status: %q, want no repair advice", err)
	}
}

// A verify that found another lifecycle run holding the lock printed an
// all-false readiness line ("installed=false version= ...") under its
// lifecycle_busy error, which read as if nothing were installed (GAP-1542).
func TestLifecycleBusyVerifyOmitsTheReadinessLine(t *testing.T) {
	busy := enterprisestatus.New(enterpriseunix.ActionVerify, "standalone", "linux", "1.0.0")
	busy.AddError("lifecycle_busy", "another DefenseClaw enterprise lifecycle run is in progress; wait for it to finish, then rerun verify")
	busy.Finish("linux", 75)
	var out bytes.Buffer
	if err := printLifecycleResult(&out, busy, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "installed=") || !strings.Contains(out.String(), "lifecycle_busy: another DefenseClaw") {
		t.Fatalf("busy verify output:\n%s", out.String())
	}

	checked := enterprisestatus.New(enterpriseunix.ActionVerify, "standalone", "linux", "1.0.0")
	checked.AddError("verify_failed", "defenseclaw-sensor-helper.service is not active")
	checked.Finish("linux", 0)
	out.Reset()
	if err := printLifecycleResult(&out, checked, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "installed=false") {
		t.Fatalf("a checked verify lost its readiness line:\n%s", out.String())
	}
}

// GAP-2028: an out-of-range --lock-wait names the cap as --help does ("15m",
// not "15m0s") and adds the usage line and --help pointer, exit 2.
func TestUnixLifecycleLockWaitOutOfRange(t *testing.T) {
	platform := "linux"
	if runtime.GOOS == "darwin" {
		platform = "macos"
	}
	cmd, _, err := rootCmd.Find([]string{"enterprise", platform, "ensure"})
	if err != nil {
		t.Fatal(err)
	}
	for wait, want := range map[time.Duration]string{
		20 * time.Minute: "--lock-wait takes at most 15m, not 20m\nUsage: ",
		-time.Second:     "--lock-wait takes a duration from 0 to 15m, not -1s\nUsage: ",
	} {
		runErr := runUnixLifecycle(cmd, platform, "ensure", &unixLifecycleOptions{lockWait: wait})
		if runErr == nil || commandExitCode(runErr) != 2 || !strings.HasPrefix(runErr.Error(), want) ||
			!strings.HasSuffix(runErr.Error(), "Try '"+cmd.CommandPath()+" --help' for help.") {
			t.Fatalf("--lock-wait %s: %v (exit %d)", wait, runErr, commandExitCode(runErr))
		}
	}
}

// GAP-2030: repair restarts the services even on a healthy deployment, and
// its output says so; with --no-start (not_started) it does not claim it.
func TestRepairOutputSaysItRestartedTheServices(t *testing.T) {
	const note = "restarted the DefenseClaw services to re-apply the deployment"
	healthy := enterprisestatus.New(enterpriseunix.ActionRepair, "standalone", "linux", "1.0.0")
	healthy.Finish("linux", 0)
	var out bytes.Buffer
	if err := printLifecycleResult(&out, healthy, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing to repair") || !strings.Contains(out.String(), note) {
		t.Fatalf("healthy repair output:\n%s", out.String())
	}
	stopped := enterprisestatus.New(enterpriseunix.ActionRepair, "standalone", "linux", "1.0.0")
	stopped.AddWarning("not_started", "installed without starting the services (--no-start)")
	stopped.Finish("linux", 0)
	out.Reset()
	if err := printLifecycleResult(&out, stopped, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), note) {
		t.Fatalf("--no-start repair claims a restart:\n%s", out.String())
	}
}

// GAP-2146, GAP-2147: a missing or doubled value source and an invalid
// --name are argument errors (usage line, --help pointer, exit 2), checked
// before the value is read or the ensure lifecycle runs.
func TestEnterpriseSecretArgumentErrorsPrintUsage(t *testing.T) {
	goos := enterpriseunix.CurrentGOOS()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	previous := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 0 }}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })

	cases := []struct {
		action, want string
		opts         enterpriseSecretOptions
	}{
		{"set", "pass exactly one of --from-stdin or --from-file", enterpriseSecretOptions{name: "ok-name"}},
		{"set", "pass exactly one of --from-stdin or --from-file", enterpriseSecretOptions{name: "ok-name", fromStdin: true, fromFile: "/etc/hostname"}},
		{"set", `--name takes lowercase letters, digits and dashes, not "BAD_NAME"`, enterpriseSecretOptions{name: "BAD_NAME", fromStdin: true}},
		{"remove", `--name takes lowercase letters, digits and dashes, not "BAD_NAME"`, enterpriseSecretOptions{name: "BAD_NAME"}},
	}
	for _, tc := range cases {
		cmd := newEnterpriseSecretCommand(tc.action, "")
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetIn(strings.NewReader("")) // an empty value must not win over the name error
		opts := tc.opts
		err := runEnterpriseSecret(cmd, tc.action, &opts)
		if err == nil {
			t.Fatalf("%s %+v succeeded", tc.action, tc.opts)
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, tc.want) || !strings.Contains(msg, "\nUsage: "+cmd.UseLine()) ||
			!strings.HasSuffix(msg, "Try '"+cmd.CommandPath()+" --help' for help.") {
			t.Fatalf("%s %+v: %q", tc.action, tc.opts, msg)
		}
		if got := commandExitCode(err); got != enterprisestatus.UnixExitInvalidArgs {
			t.Fatalf("%s %+v exits %d", tc.action, tc.opts, got)
		}
		if out.Len() != 0 {
			t.Fatalf("%s %+v ran the lifecycle: %q", tc.action, tc.opts, out.String())
		}
	}
}

// secret set and secret remove both printed only "✓ ensure: done" and the
// apply steps; each names the command and the credential it changed
// (GAP-2305).
func TestSecretChangeOutputNamesTheCommandAndCredential(t *testing.T) {
	applied := func() *enterprisestatus.Result {
		result := enterprisestatus.New(enterpriseunix.ActionEnsure, "standalone", "linux", "1.0.0")
		result.OK = true
		result.Changes = []string{"applied the changed secrets"}
		return result
	}
	for _, tc := range []struct {
		action  string
		existed bool
		want    string
	}{
		{"set", false, "✓ secret set: done\n  - stored credential dctest-cred\n  - applied the changed secrets\n"},
		{"remove", true, "✓ secret remove: done\n  - removed credential dctest-cred\n  - applied the changed secrets\n"},
		{"remove", false, "  - credential dctest-cred was not stored; nothing to remove\n"},
	} {
		result := applied()
		var out bytes.Buffer
		if err := printLifecycleResult(&out, describeSecretChange(result, tc.action, "dctest-cred", tc.existed), false); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), tc.want) || strings.Contains(out.String(), "ensure") {
			t.Fatalf("secret %s output = %q", tc.action, out.String())
		}
		if result.Action != enterpriseunix.ActionEnsure || len(result.Changes) != 1 {
			t.Fatalf("the JSON result changed: %+v", result)
		}
	}
	failed := enterprisestatus.New(enterpriseunix.ActionEnsure, "standalone", "linux", "1.0.0")
	failed.AddError("change_failed", "the installed config still references credential dctest-cred")
	shown := describeSecretChange(failed, "remove", "dctest-cred", true)
	if shown.Action != "secret remove" || len(shown.Changes) != 0 {
		t.Fatalf("failed remove = %+v", shown)
	}
}

// GAP-2329: a malformed --lock-wait gives examples inside the 15m cap, and
// the cap error names the value as typed ("not 1h", not "not 60m").
func TestUnixLifecycleLockWaitMessagesStayInsideTheCap(t *testing.T) {
	platform := "linux"
	if runtime.GOOS == "darwin" {
		platform = "macos"
	}
	cmd, _, err := rootCmd.Find([]string{"enterprise", platform, "ensure"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		v := cmd.Flags().Lookup("lock-wait").Value.(*lockWaitValue)
		*v.wait, v.typed = 0, ""
	})
	if got := plainFlagValueError(cmd.ParseFlags([]string{"--lock-wait=banana"})); got != `--lock-wait takes a duration from 0 to 15m, such as 30s or 5m, not "banana"` {
		t.Fatalf("--lock-wait banana: %q", got)
	}
	if err := cmd.ParseFlags([]string{"--lock-wait=1h"}); err != nil {
		t.Fatal(err)
	}
	opts := &unixLifecycleOptions{lockWait: time.Hour}
	runErr := runUnixLifecycle(cmd, platform, "ensure", opts)
	if runErr == nil || commandExitCode(runErr) != 2 || !strings.HasPrefix(runErr.Error(), "--lock-wait takes at most 15m, not 1h\nUsage: ") {
		t.Fatalf("--lock-wait 1h: %v (exit %d)", runErr, commandExitCode(runErr))
	}
	if strings.Contains(cmd.Flags().FlagUsages(), "default 0") {
		t.Fatalf("--help shows a zero default:\n%s", cmd.Flags().FlagUsages())
	}
}

// GAP-2330: a stray argument on a lifecycle or secret leaf is an
// "unexpected argument", as on every other gateway command, not an
// "unknown command"; enterprise hooks status no longer ignores it.
func TestEnterpriseLeavesRejectAStrayArgumentAsUnexpected(t *testing.T) {
	installUsageArgChecks(rootCmd)
	platform := "linux"
	if runtime.GOOS == "darwin" {
		platform = "macos"
	}
	for _, path := range [][]string{
		{"enterprise", platform, "ensure"},
		{"enterprise", platform, "status"},
		{"enterprise", "secret", "status"},
		{"enterprise", "hooks", "status"},
	} {
		cmd, _, err := rootCmd.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		got := cmd.ValidateArgs([]string{"extra-arg"})
		want := `unexpected argument "extra-arg" for "` + cmd.CommandPath() + `"` + "\nUsage: "
		if got == nil || commandExitCode(got) != 2 || !strings.HasPrefix(got.Error(), want) {
			t.Fatalf("%v extra-arg: exit %d, %v", path, commandExitCode(got), got)
		}
		if err := cmd.ValidateArgs(nil); err != nil {
			t.Fatalf("%v without arguments: %v", path, err)
		}
	}
}
