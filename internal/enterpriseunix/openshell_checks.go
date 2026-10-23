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

package enterpriseunix

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/posixacl"
)

// The install-mode verify rows. They answer one question for the
// administrator: can users on this host run sandboxes, and if not, what is
// missing and what to run. A row is a service line of kind "sandbox" in the
// result (status and verify print it with the units) and a missing one is a
// warning with the code openshell_prerequisite_missing: the deployment itself
// is healthy, and the gateway refuses the sandbox runs of users until it is
// fixed.

// sandboxHostArch is the CPU architecture of this host (tests replace it).
var sandboxHostArch = runtime.GOARCH

// prereqRow is one verified prerequisite.
type prereqRow struct {
	Name   string
	OK     bool
	Detail string
	// Fix is what the administrator runs or sets; empty for an OK row.
	Fix string
	// Code is the warning code of a missing row ("" is
	// openshell_prerequisite_missing).
	Code string
	// Version is the release an OpenShell part row read from the
	// administrator's trusted copy, also when it is not one the pin allows
	// ("" for other rows and when it could not be read).
	Version string
}

// checkLauncher is a row only when the launcher path holds a file the
// lifecycle does not own (see foreignLauncher): users then run that file, not
// the sandbox launcher, so sandboxes cannot run, and DefenseClaw is otherwise
// healthy.
func (e *Env) checkLauncher() (prereqRow, bool) {
	if !e.foreignLauncher() {
		return prereqRow{}, false
	}
	path := e.launcherPath()
	return prereqRow{Name: "launcher", Code: codeLauncherConflict,
		Detail: fmt.Sprintf("%s exists and is not a symlink (a Python DefenseClaw install, say), so the lifecycle leaves it alone and users do not get the sandbox launcher", path),
		Fix:    fmt.Sprintf("move %s aside or remove it, then run `%s`", path, e.lifecycleCommand(ActionEnsure))}, true
}

// currentOpenShellSettings are the settings the result describes: the plan of
// the running transaction, else what the last commit applied.
func (l *lifecycle) currentOpenShellSettings() (openshellSettings, bool) {
	if l.osPlan != nil {
		return l.osPlan.settings, l.osPlan.settings.Enabled
	}
	applied := l.env.loadOpenShellState().Applied
	if applied == nil || !applied.Enabled {
		return openshellSettings{}, false
	}
	return openshellSettings{Enabled: true, Install: applied.Install, Driver: applied.Driver, Fallback: applied.Fallback, Version: applied.Version,
		GatewayPort: applied.GatewayPort, E2fsprogsDir: applied.E2fsprogsDir}, true
}

// describeOpenShell adds the sandbox rows to the result and warns for every
// prerequisite the host lacks and every change still waiting for sandboxes
// to stop.
func (l *lifecycle) describeOpenShell(ctx context.Context) {
	env, r := l.env, l.result
	settings, on := l.currentOpenShellSettings()
	state := env.loadOpenShellState()
	if on || len(state.Pending) > 0 {
		l.describeLegacySandboxes(ctx)
	}
	if !on {
		for _, entry := range state.sortedPending() {
			if entry.Kind == "stop" {
				l.describePending(entry)
			}
		}
		l.noteOpenShellCapability(ctx, settings, false, nil, nil)
		return
	}
	row := func(name, state string) {
		r.Services = append(r.Services, enterprisestatus.Service{Name: "sandbox " + name, Kind: sandboxRowKind, State: state, Required: false})
	}
	row("openshell", fmt.Sprintf("enabled, install=%s driver=%s%s gateway=127.0.0.1:%d%s", settings.Install, settings.Driver,
		fallbackNote(settings), settings.GatewayPort, versionNote(settings.Version)))
	primary, fallback := env.checkOpenShellDrivers(ctx, settings)
	l.noteOpenShellCapability(ctx, settings, true, primary, fallback)
	fallbackReady := fallback != nil && rowsReady(fallback)
	for _, check := range primary {
		if check.OK {
			row(check.Name, "ok: "+check.Detail)
			continue
		}
		row(check.Name, "missing: "+check.Detail)
		switch {
		case check.Code == codeLauncherConflict:
			r.AddWarning(codeLauncherConflict, fmt.Sprintf("users do not get `defenseclaw sandbox` on this host: %s; %s", check.Detail, check.Fix))
		case fallbackReady && microVMItem(check.Name):
			// Users still get sandboxes: the docker fallback, with every
			// profile floor unchanged.
			r.AddWarning(codeDriverFallback, fmt.Sprintf("MicroVM sandboxes cannot run on this host (%s): %s; users get docker sandboxes instead "+
				"(enterprise.openshell.driver_fallback: docker); for MicroVMs: %s", check.Name, check.Detail, check.Fix))
		default:
			r.AddWarning(codeOpenShellPrerequisite, fmt.Sprintf("sandboxes cannot run for users on this host (%s): %s; %s", check.Name, check.Detail, check.Fix))
		}
	}
	// The docker fallback's own rows (those the MicroVM rows do not
	// already show).
	shown := map[string]bool{}
	for _, check := range primary {
		shown[check.Name] = true
	}
	for _, check := range fallback {
		if shown[check.Name] {
			continue
		}
		if check.OK {
			row("fallback "+check.Name, "ok: "+check.Detail)
			continue
		}
		row("fallback "+check.Name, "missing: "+check.Detail)
		r.AddWarning(codeDriverFallback, fmt.Sprintf("the docker fallback cannot run for users on this host (%s): %s; %s; users without KVM get no sandbox until it is fixed",
			check.Name, check.Detail, check.Fix))
	}
	groups, dockerMembers := env.groupRows(ctx, settings)
	for _, group := range groups {
		if group.OK {
			row(group.Name, "ok: "+group.Detail)
			continue
		}
		row(group.Name, "missing: "+group.Detail)
		r.AddWarning(codeSandboxGroups, fmt.Sprintf("%s; %s", group.Detail, group.Fix))
	}
	if dockerMembers != "" {
		r.AddWarning(codeDockerGroupMembers, dockerMembers)
	}
	if settings.Install == config.EnterpriseOpenShellInstallSetup {
		for _, line := range env.userInstalls(ctx) {
			row("user-installed", line+" (user-installed, unmanaged)")
		}
	}
	for _, entry := range state.sortedPending() {
		l.describePending(entry)
	}
	l.describeMacOSAgents(ctx)
	// The gateway reads this to say, in its own words, why a host run of a
	// required agent cannot move into a sandbox. status and verify only read.
	if l.opts.Action != ActionStatus && l.opts.Action != ActionVerify {
		if err := env.publishPrerequisites(ctx, settings); err != nil {
			r.AddWarning(codeState, "could not record "+openshell.PrerequisitesFile+": "+err.Error())
		}
	}
}

// describeLegacySandboxes reports, for every account whose sandbox daemon
// runs, each legacy sandbox as running unprotected (GAP-0901): a live guest
// whose session runs the supervisor of an OpenShell release older than the
// oldest supported one, whose network broker can let its connections bypass
// sandbox policy and which DefenseClaw cannot contain
// (sandboxapi.Status.Unprotected), and every sandbox that a daemon of
// DefenseClaw 1.0.3 or older still holds. Each is a row and a warning with
// the command its user runs to end it, since DefenseClaw stops none itself
// and the account's daemon runs no new sandbox until it is gone; the
// deployment is then not security-complete, and verify fails. A daemon that
// runs but cannot answer is reported the same way: what cannot be shown
// protected is not. A user daemon runs only under a running user manager
// (Linux: the signed-in and lingering accounts).
func (l *lifecycle) describeLegacySandboxes(ctx context.Context) {
	ops := l.env.sandboxOps()
	accounts := ops.LoggedIn(ctx)
	if l.env.GOOS == "darwin" {
		accounts = ops.Accounts(ctx)
	}
	seen := map[int]bool{}
	for _, a := range accounts {
		if seen[a.UID] {
			continue
		}
		seen[a.UID] = true
		st, err := ops.Status(ctx, a)
		var lines []string
		switch {
		case err != nil:
			lines = []string{"its sandbox daemon could not say whether one runs (" + err.Error() + "); as " + a.Name + ", `defenseclaw sandbox status` names any"}
		case st.Legacy && st.busy() > 0:
			held := "1 sandbox"
			if n := st.busy(); n != 1 {
				held = fmt.Sprintf("%d sandboxes", n)
			}
			lines = []string{"the sandbox daemon of an earlier DefenseClaw holds " + held + ", which this version cannot show protected; as " + a.Name +
				", `defenseclaw sandbox list` names them, and `defenseclaw sandbox stop NAME` ends a running one"}
		default:
			for _, u := range st.Unprotected {
				lines = append(lines, u.Name+"; as "+a.Name+", `"+u.Stop+"` ends it")
			}
		}
		for _, line := range lines {
			l.result.Services = append(l.result.Services, enterprisestatus.Service{Name: "sandbox unprotected " + a.Name, Kind: sandboxRowKind,
				State: sandboxapi.LegacyUnprotected + ": " + line})
			l.result.AddWarning(codeLegacySandbox, a.Name+": "+sandboxapi.LegacyUnprotected+": "+line+". Its session runs the supervisor of an OpenShell "+
				"release older than "+openshell.SupportedMin+", whose network broker can let its connections bypass sandbox policy and DefenseClaw cannot "+
				"contain; DefenseClaw stops no sandbox for its user, and runs no new sandbox for "+a.Name+" until it is gone")
			l.result.SecurityComplete = false
		}
	}
}

// fallbackNote names the docker fallback in the openshell row.
func fallbackNote(s openshellSettings) string {
	if s.Fallback == "" {
		return ""
	}
	return " fallback=" + s.Fallback
}

// checkOpenShellDrivers verifies the install mode's prerequisites for the
// wanted driver and, where users whose KVM does not work fall back to
// docker, for the fallback (nil otherwise).
func (e *Env) checkOpenShellDrivers(ctx context.Context, s openshellSettings) (primary, fallback []prereqRow) {
	primary = e.checkOpenShell(ctx, s)
	if e.GOOS == "linux" && s.dockerFallback() {
		fallback = e.checkOpenShell(ctx, s.fallbackSettings())
	}
	return primary, fallback
}

// rowsReady reports whether every row is OK.
func rowsReady(rows []prereqRow) bool {
	for _, row := range rows {
		if !row.OK {
			return false
		}
	}
	return true
}

// microVMItem reports whether a row is one only the MicroVM driver needs.
func microVMItem(name string) bool {
	switch name {
	case "microvm driver", "e2fsprogs", "kvm":
		return true
	}
	return false
}

func versionNote(version string) string {
	if version == "" {
		return ""
	}
	return " version=" + version
}

// describePending reports a change that waits for an account's sandboxes.
func (l *lifecycle) describePending(entry pending) {
	waiting := fmt.Sprintf("%d sandboxes run (or are starting, stopping, or a MicroVM that OpenShell does not report stopped)", entry.Sandboxes)
	switch {
	case entry.Sandboxes < 0:
		waiting = "the lifecycle could not tell whether sandboxes run"
	case entry.Sandboxes == 1:
		waiting = "1 sandbox runs (or is starting, stopping, or a MicroVM that OpenShell does not report stopped)"
	case entry.Sandboxes == 0:
		waiting = "waiting to be tried again"
	}
	l.result.Services = append(l.result.Services, enterprisestatus.Service{
		Name: "sandbox pending " + entry.User, Kind: sandboxRowKind, State: fmt.Sprintf("%s since %s: %s", entry.Kind, entry.Since, waiting),
	})
	if entry.Kind == "launchd" {
		l.result.AddWarning(codeSandboxPending, fmt.Sprintf("pending launchd for user %s since %s (%s): %s; a root ensure, repair or reconcile run applies the LaunchAgent reload after this account's sandboxes stop. The first sandbox started after the running ones stop also reloads the job itself. If that reload fails, the start reports it and names `sudo %s`",
			entry.User, entry.Since, entry.reasonBase(), waiting, l.env.lifecycleCommand(ActionRepair)))
		return
	}
	l.result.AddWarning(codeSandboxPending, fmt.Sprintf("pending %s for user %s since %s (%s): %s; it is applied by the first run of `%s` or the user's next `defenseclaw sandbox` command that finds no sandbox running. "+
		"The user's `defenseclaw sandbox stop NAME` flushes and stops a running one; a MicroVM whose workload completed or that is in OpenShell's error state, "+
		"which OpenShell does not stop and whose VM may still run, holds the change until OpenShell reports it stopped (the user's `defenseclaw sandbox stop NAME` says how) "+
		"or the user deletes it (`defenseclaw sandbox delete NAME`)",
		entry.Kind, entry.User, entry.Since, entry.reasonBase(), waiting, l.env.lifecycleCommand(ActionEnsure)))
}

// checkOpenShell verifies the prerequisites of the install mode.
func (e *Env) checkOpenShell(ctx context.Context, s openshellSettings) []prereqRow {
	var rows []prereqRow
	if s.Install == config.EnterpriseOpenShellInstallSetup {
		rows = e.checkSetupMode(ctx, s)
	} else {
		rows = e.checkPrerequisiteMode(ctx, s)
	}
	if row, conflict := e.checkLauncher(); conflict {
		rows = append(rows, row)
	}
	return rows
}

// binCandidates are where an administrator's OpenShell puts its CLI and
// gateway, the root-owned places first: on a Mac /usr/local/bin, where the
// administrator copies NVIDIA's release binaries as root, before a Homebrew
// prefix, which belongs to the account that ran brew.
func (e *Env) binCandidates(name string) []string {
	if e.GOOS == "darwin" {
		return []string{"/usr/local/bin/" + name, "/opt/homebrew/bin/" + name}
	}
	return []string{"/usr/bin/" + name, "/usr/local/bin/" + name}
}

func (e *Env) firstExisting(paths []string) string {
	for _, p := range paths {
		if exists(e.P(p)) {
			return p
		}
	}
	return ""
}

// trustedAdminFile is the first of paths that exists and passes the managed
// trust check (root-owned, closed to other writers, no link on the way);
// refused names every one before it that exists but fails the check. The
// lifecycle runs only such a file as root, and a managed sandbox uses only
// the administrator's root-owned OpenShell or the account's own, never a
// copy another account can change (GAP-0189).
func (e *Env) trustedAdminFile(paths []string) (found string, refused []string) {
	for _, p := range paths {
		if !exists(e.P(p)) {
			continue
		}
		if err := e.Trust(e.P(p), TrustAdminFile); err != nil {
			refused = append(refused, fmt.Sprintf("%s (%v)", p, err))
			continue
		}
		return p, refused
	}
	return "", refused
}

// untrustedDetail says that what is installed is not the administrator's.
func untrustedDetail(name string, refused []string) string {
	return fmt.Sprintf("%s is installed only where an account other than root can change it: %s; the lifecycle and the managed sandboxes do not use it",
		name, strings.Join(refused, "; "))
}

// openshellInstallFix is how the administrator installs OpenShell for the
// prerequisite mode.
func (e *Env) openshellInstallFix() string {
	if e.GOOS == "darwin" {
		return "install OpenShell " + openshell.InstallerVersion + " root-owned: copy NVIDIA's release binaries into /usr/local/bin (and openshell-driver-vm into /usr/local/libexec/openshell) as root, " +
			"since a Homebrew prefix belongs to the account that ran brew; or set enterprise.openshell.install: setup so users install it themselves"
	}
	return "install OpenShell " + openshell.InstallerVersion + " from NVIDIA's release packages (openshell and openshell-gateway), or set enterprise.openshell.install: setup so users install it themselves"
}

// installedOpenShellVersion finds the release of one part of the
// administrator's OpenShell: its package pkg in the package database first
// (Linux; "" for a part no package carries), then the binary at path itself,
// which the caller found through trustedAdminFile, so root can run it.
func (e *Env) installedOpenShellVersion(ctx context.Context, pkg, path string) (v openshell.Version, how string, err error) {
	if e.GOOS == "linux" && pkg != "" {
		if res, rerr := e.Runner.Run(ctx, "rpm", "-q", "--qf", "%{VERSION}", pkg); rerr == nil && res.ExitCode == 0 {
			if v, perr := openshell.ParseVersion(string(res.Stdout)); perr == nil {
				return v, "the " + pkg + " package", nil
			}
		}
		if res, rerr := e.Runner.Run(ctx, "dpkg", "-s", pkg); rerr == nil && res.ExitCode == 0 {
			for _, line := range strings.Split(string(res.Stdout), "\n") {
				if value, ok := strings.CutPrefix(line, "Version:"); ok {
					if v, perr := openshell.ParseVersion(strings.TrimSpace(value)); perr == nil {
						return v, "the " + pkg + " package", nil
					}
				}
			}
		}
	}
	if path == "" {
		return openshell.Version{}, "", fmt.Errorf("not installed")
	}
	v, err = e.openshellBinaryVersion(ctx, path)
	if err != nil {
		return openshell.Version{}, "", err
	}
	return v, path, nil
}

// openshellBinaryVersion runs a trusted OpenShell binary's --version.
func (e *Env) openshellBinaryVersion(ctx context.Context, path string) (openshell.Version, error) {
	res, err := e.Runner.Run(ctx, e.P(path), "--version")
	if err != nil {
		return openshell.Version{}, fmt.Errorf("%s --version: %v", path, err)
	}
	return openshell.VersionFromOutput(strings.TrimSpace(string(res.Stdout)))
}

var versionRange = regexp.MustCompile(`^>=([0-9]+\.[0-9]+\.[0-9]+)(?: <([0-9]+\.[0-9]+\.[0-9]+))?$`)

// versionAllowed reports whether have satisfies enterprise.openshell.version:
// an exact release, a ">=x <y" range, or (empty) the releases DefenseClaw
// supports.
func versionAllowed(spec string, have openshell.Version) (bool, string) {
	spec = strings.TrimSpace(spec)
	if err := openshell.CheckSandboxRelease(have); err != nil && openshell.Legacy(have) {
		// Whatever the pin allows: each user's daemon starts no sandbox on it.
		return false, err.Error()
	}
	switch {
	case spec == "":
		if err := openshell.CheckSupported(have); err != nil {
			return false, err.Error()
		}
		return true, ""
	case versionRange.MatchString(spec):
		m := versionRange.FindStringSubmatch(spec)
		low, _ := openshell.ParseVersion(m[1])
		if have.Compare(low) < 0 {
			return false, fmt.Sprintf("%s is older than %s", have, m[1])
		}
		if m[2] != "" {
			// A prerelease of the ceiling is outside the range, as the
			// ceiling is.
			if high, _ := openshell.ParseVersion(m[2]); have.Release().Compare(high) >= 0 {
				return false, fmt.Sprintf("%s is %s or newer", have, m[2])
			}
		}
		return true, ""
	}
	want, err := openshell.ParseVersion(spec)
	if err != nil {
		return false, err.Error()
	}
	if have.Compare(want) != 0 {
		return false, fmt.Sprintf("%s is installed, enterprise.openshell.version pins %s", have, want)
	}
	return true, ""
}

// checkPrerequisiteMode: the administrator installed OpenShell; the rows are
// what the sandbox daemon of every user will insist on. Each part (CLI,
// gateway, MicroVM driver) is the administrator's root-owned copy, its
// release satisfies enterprise.openshell.version, and all of them are one
// release: a gateway runs only the MicroVM driver of its own (GAP-0245,
// GAP-0277).
func (e *Env) checkPrerequisiteMode(ctx context.Context, s openshellSettings) []prereqRow {
	var rows []prereqRow
	installFix := e.openshellInstallFix()
	pinFix := "install a release that satisfies enterprise.openshell.version" + versionNote(s.Version) + " (" + installFix + ")"
	if v, err := openshell.ParseVersion(s.Version); err == nil && openshell.CheckSandboxRelease(v) != nil {
		// No release satisfies both the pin and openshell.SupportedMin.
		pinFix = "set enterprise.openshell.version to " + openshell.InstallerVersion + " (or a range from " + openshell.SupportedMin +
			") and install that release (" + installFix + ")"
	}
	var parts []string
	releases := map[string]openshell.Version{}
	part := func(row, name, pkg, path string, refused []string, fix string) {
		if path == "" && len(refused) > 0 {
			rows = append(rows, prereqRow{Name: row, Detail: untrustedDetail(name, refused), Fix: fix})
			return
		}
		version, how, err := e.installedOpenShellVersion(ctx, pkg, path)
		switch {
		case err != nil && path == "":
			rows = append(rows, prereqRow{Name: row, Detail: name + " is not installed", Fix: fix})
			return
		case err != nil && s.Version != "":
			rows = append(rows, prereqRow{Name: row, Detail: fmt.Sprintf("found %s, but its version could not be read (%v), so the pin enterprise.openshell.version %q cannot be checked", path, err, s.Version), Fix: pinFix})
			return
		case err != nil:
			// Without a pin, unverifiable is not missing: say so without
			// failing the host.
			rows = append(rows, prereqRow{Name: row, OK: true, Detail: "found " + path + "; version not checked: " + err.Error()})
			return
		}
		parts, releases[name] = append(parts, name), version
		if ok, why := versionAllowed(s.Version, version); !ok {
			rows = append(rows, prereqRow{Name: row, Detail: name + ": " + why, Fix: pinFix, Version: version.String()})
			return
		}
		rows = append(rows, prereqRow{Name: row, OK: true, Detail: fmt.Sprintf("%s (%s)", version, how), Version: version.String()})
	}
	cli, refused := e.trustedAdminFile(e.binCandidates("openshell"))
	part("openshell cli", "openshell", "openshell", cli, refused, installFix)
	gw, refused := e.trustedAdminFile(e.binCandidates("openshell-gateway"))
	part("openshell gateway", "openshell-gateway", "openshell-gateway", gw, refused, installFix)
	if s.wantsVM() {
		dir, refused := e.systemDriver()
		driver := ""
		if dir != "" {
			driver = filepath.Join(dir, "openshell-driver-vm")
		}
		part("microvm driver", "openshell-driver-vm", "", driver, refused, adminVMDriverFixText(e.GOOS))
	}
	if len(parts) > 1 {
		var named []string
		same := true
		for _, name := range parts {
			named = append(named, name+" "+releases[name].String())
			same = same && releases[name].Compare(releases[parts[0]]) == 0
		}
		if same {
			rows = append(rows, prereqRow{Name: "openshell release", OK: true, Detail: strings.Join(parts, ", ") + " are all " + releases[parts[0]].String()})
		} else {
			rows = append(rows, prereqRow{Name: "openshell release", Detail: strings.Join(named, ", ") + " are not one release, and a gateway runs only the MicroVM driver and CLI of its own",
				Fix: "install " + strings.Join(parts, ", ") + " from one OpenShell release" + versionNote(s.Version) + " (" + installFix + ")"})
		}
	}
	rows = append(rows, e.checkDriver(ctx, s)...)
	return rows
}

// adminVMDriverFixText is the microvm driver row's fix: the shared
// openshell.AdminVMDriverFix the managed user's doctor names too, with its
// pinned-digest command (GAP-0481).
func adminVMDriverFixText(goos string) string {
	fix := openshell.AdminVMDriverFix(goos, sandboxHostArch)
	text := fix.Summary
	if fix.Command != "" {
		text += ": " + fix.Command
	}
	return text + "; or use enterprise.openshell.install: setup"
}

// checkDriver checks what the compute driver needs from the host.
func (e *Env) checkDriver(ctx context.Context, s openshellSettings) []prereqRow {
	var rows []prereqRow
	if s.wantsVM() {
		rows = append(rows, e.checkE2fsprogs(ctx, s)...)
		if e.GOOS == "linux" {
			// No umask row: the gateway runs only in DefenseClaw's own unit,
			// whose exec shim sets umask 0022 whatever the unit or a drop-in
			// says; NVIDIA's openshell-gateway.service is never run, so a
			// drop-in there changes nothing (GAP-0472).
			rows = append(rows, e.checkKVM())
		}
	}
	if s.Driver == config.EnterpriseOpenShellDriverDocker || e.GOOS == "darwin" {
		row := e.checkDocker()
		if s.wantsVM() {
			// Not a leftover of the docker driver: on a Mac the MicroVM driver
			// boots the harness images DefenseClaw builds in the local Docker.
			// Docker Desktop runs per account, so the engine is checked per
			// user by `sandbox doctor` and at sandbox start (GAP-0443).
			row.Detail += "; the MicroVM driver boots the harness images built in each user's Docker, which must run for that user (sandbox doctor checks it)"
		}
		rows = append(rows, row)
	}
	return rows
}

// checkSetupMode: DefenseClaw installs nothing here; each user's daemon
// installs the pinned release into the user's home. The rows say the pin is
// one this build can install and the platform is one NVIDIA publishes.
func (e *Env) checkSetupMode(ctx context.Context, s openshellSettings) []prereqRow {
	var rows []prereqRow
	switch {
	case s.Version == "":
		rows = append(rows, prereqRow{Name: "openshell pin", Detail: "setup mode needs enterprise.openshell.version to be an exact release", Fix: "set enterprise.openshell.version: " + openshell.InstallerVersion})
	case versionRange.MatchString(s.Version) || openshell.TarballPins[s.Version] == nil:
		rows = append(rows, prereqRow{Name: "openshell pin", Detail: fmt.Sprintf("%q is not a release this DefenseClaw build can install", s.Version),
			Fix: "set enterprise.openshell.version to one of: " + strings.Join(openshell.PinnedTarballReleases(), ", ")})
	case s.RaisedFrom != "":
		rows = append(rows, prereqRow{Name: "openshell pin", OK: true, Detail: s.Version + " from NVIDIA's release tarballs, verified against their checksums and the digests this build pins; " +
			"enterprise.openshell.version pins " + s.RaisedFrom + ", which runs no sandbox (" + openshell.SupportedMin + " closes a network-broker policy bypass, " +
			"NVIDIA/OpenShell#4494), so each user's OpenShell moves to " + s.Version + " once none of the user's sandboxes runs; set the pin to " + s.Version})
	default:
		rows = append(rows, prereqRow{Name: "openshell pin", OK: true, Detail: s.Version + " from NVIDIA's release tarballs, verified against their checksums and the digests this build pins"})
	}
	if e.GOOS == "darwin" && sandboxHostArch != "arm64" {
		rows = append(rows, prereqRow{Name: "openshell platform", Detail: "NVIDIA publishes no OpenShell tarballs for Intel Macs", Fix: "use install: prerequisite with an OpenShell you install"})
	}
	rows = append(rows, e.checkDriver(ctx, s)...)
	return rows
}

// checkE2fsprogs: the MicroVM driver on a Mac needs e2fsprogs in a
// directory the administrator vouches for (spec D5); on Linux the host's.
func (e *Env) checkE2fsprogs(ctx context.Context, s openshellSettings) []prereqRow {
	if e.GOOS == "linux" {
		if p := e.firstExisting([]string{"/usr/sbin/mke2fs", "/sbin/mke2fs", "/usr/bin/mke2fs"}); p != "" {
			return []prereqRow{{Name: "e2fsprogs", OK: true, Detail: p}}
		}
		return []prereqRow{{Name: "e2fsprogs", Detail: "mke2fs is not installed", Fix: "install e2fsprogs 1.43 or newer"}}
	}
	result := e.CheckE2fsprogsDir(s.E2fsprogsDir)
	if result.ToolDir != "" {
		return []prereqRow{{Name: "e2fsprogs", OK: true, Detail: result.ToolDir}}
	}
	return []prereqRow{{Name: "e2fsprogs", Detail: result.Problem, Fix: result.Fix}}
}

// E2fsprogsCheckResult is the administrator's macOS prerequisite verdict.
// ToolDir is the exact folder the managed gateway uses; when empty, Problem
// and Fix explain the refusal. The cross-component regression test checks
// this verdict against the real gateway plan and managed doctor row.
type E2fsprogsCheckResult struct {
	ToolDir, Problem, Fix string
}

// CheckE2fsprogsDir is checkE2fsprogs's macOS directory decision.
func (e *Env) CheckE2fsprogsDir(dir string) E2fsprogsCheckResult {
	if dir == "" {
		if info, err := os.Stat(e.P(openshell.PackageE2fsprogsDir)); err == nil && info.IsDir() {
			dir = openshell.PackageE2fsprogsDir
		} else {
			return E2fsprogsCheckResult{Problem: "enterprise.openshell.e2fsprogs_dir is not set and the managed package has no e2fsprogs; each account needs its own ~/.local/opt/e2fsprogs build",
				Fix: "install the managed package with e2fsprogs, or install e2fsprogs 1.43 or newer into a root-owned directory and set enterprise.openshell.e2fsprogs_dir"}
		}
	}
	trust := e.Trust
	if trust == nil {
		trust = defaultTrust
	}
	if err := trust(e.P(dir), TrustRulePack); err != nil {
		return E2fsprogsCheckResult{Problem: fmt.Sprintf("%s is not an administrator-controlled directory (%v), so it is refused", dir, err),
			Fix: "make the directory tree root-owned and closed to other writers (chown -R root:wheel; chmod -R go-w)"}
	}
	// The folder the gateway's exec shim puts first on the driver's PATH,
	// found by the same rule (GAP-0506): ensure used to accept the tools in
	// any of sbin, bin or the folder itself while the shim took only sbin,
	// so an accepted e2fsprogs_dir could leave the gateway unable to start.
	tools := openshell.AdminE2fsprogsToolDir(dir, func(p string) bool { return openshell.RegularFile(e.P(p)) })
	if tools == "" {
		return E2fsprogsCheckResult{Problem: fmt.Sprintf("%s holds no mke2fs and debugfs side by side, in it or in its sbin or bin", dir),
			Fix: "install e2fsprogs 1.43 or newer there, or set enterprise.openshell.e2fsprogs_dir to its install prefix or to the folder that holds both mke2fs and debugfs"}
	}
	if problem := openshell.E2fsprogsAccessProblem(tools, func(path string) (os.FileInfo, error) { return os.Stat(e.P(path)) }); problem != "" {
		return E2fsprogsCheckResult{Problem: problem,
			Fix: "make the administrator's e2fsprogs directory and its ancestors traversable and both tools executable by sandbox accounts (chmod o+x)"}
	}
	return E2fsprogsCheckResult{ToolDir: tools}
}

// kvmDevice is the device a MicroVM needs.
const kvmDevice = "/dev/kvm"

func (e *Env) checkKVM() prereqRow {
	info, err := os.Stat(e.P(kvmDevice))
	if err != nil {
		return prereqRow{Name: "kvm", Detail: kvmDevice + " does not exist: the CPU's virtualization is off or not passed to this machine",
			Fix: "enable hardware virtualization (nested virtualization on a cloud VM), or use enterprise.openshell.driver: docker"}
	}
	if info.Mode().Perm()&0o006 == 0o006 {
		return prereqRow{Name: "kvm", OK: true, Detail: kvmDevice + " is readable and writable by every user"}
	}
	return prereqRow{Name: "kvm", OK: true, Detail: kvmDevice + " needs the kvm group or a read-write user ACL"}
}

// dockerSockets are where the Docker engine listens on Linux and macOS.
var dockerSockets = []string{"/var/run/docker.sock", "/run/docker.sock"}

func (e *Env) checkDocker() prereqRow {
	cli := e.firstExisting(append(e.binCandidates("docker"), "/Applications/Docker.app/Contents/Resources/bin/docker"))
	sock := e.firstExisting(dockerSockets)
	switch {
	case cli == "" && sock == "":
		return prereqRow{Name: "docker", Detail: "Docker is not installed", Fix: "install Docker Engine (Docker Desktop on a Mac); the sandbox images are built and run through it"}
	case cli == "":
		return prereqRow{Name: "docker", OK: true, Detail: sock + " answers; the docker CLI was not found in the usual places"}
	}
	return prereqRow{Name: "docker", OK: true, Detail: cli}
}

// groupRows is the groups rows (Linux). Each account that uses sandboxes
// needs the docker group: the docker driver runs in Docker, and the MicroVM
// driver (and its docker fallback) boots the agent images DefenseClaw builds
// in Docker for each account (GAP-0511). The MicroVM driver also needs the
// kvm group or a named user ACL where /dev/kvm is not open to everyone. The accounts are those
// that used sandboxes (a registration or decision record, or sandbox state of
// their own in the home), never every enrolled one: administrators and
// service accounts that never run a sandbox do not belong in the
// root-equivalent docker group (GAP-0454). Each row is one summary line with
// one generic fix. advisory is the docker_group_members warning over every
// enrolled account ("" when none is in the group, GAP-0498).
func (e *Env) groupRows(ctx context.Context, s openshellSettings) (rows []prereqRow, advisory string) {
	vm := s.wantsVM()
	if e.GOOS != "linux" || (s.Driver != config.EnterpriseOpenShellDriverDocker && !vm) {
		return nil, ""
	}
	kvm, kvmErr := os.Stat(e.P(kvmDevice))
	needKVM := vm && kvmErr == nil && kvm.Mode().Perm()&0o006 != 0o006
	var kvmACL posixacl.View
	var kvmACLErr error
	if needKVM {
		kvmACL, kvmACLErr = posixacl.ReadAccessXattr(e.P(kvmDevice))
	}
	ops := e.sandboxOps()
	var accounts []SandboxAccount
	var enrolled, members int
	groupsOf := map[int][]string{}
	for _, a := range ops.Accounts(ctx) {
		groups, err := ops.Groups(ctx, a)
		if err == nil {
			groupsOf[a.UID] = groups
			enrolled++
			if contains(groups, "docker") {
				members++
			}
		}
		if e.hasHomeSandboxState(a) {
			accounts = append(accounts, a)
		}
	}
	advisory = e.dockerGroupAdvisory(members, enrolled)
	if len(accounts) == 0 {
		need := "docker"
		if needKVM {
			need = "kvm (or a /dev/kvm user ACL) and docker"
		}
		return []prereqRow{{Name: "groups", OK: true, Detail: fmt.Sprintf("no account has used sandboxes yet; each account that runs them needs the %s group", need)}}, advisory
	}
	var noKVM, noDocker []string
	for _, a := range accounts {
		groups, ok := groupsOf[a.UID]
		if !ok {
			continue
		}
		hasKVM := contains(groups, "kvm") && kvmACLErr == nil
		if needKVM {
			if found, allowed := kvmACL.NamedUserAllows(a.UID, 0o6); found {
				hasKVM = allowed
			}
		}
		if needKVM && !hasKVM {
			noKVM = append(noKVM, a.Name)
		}
		if !contains(groups, "docker") {
			noDocker = append(noDocker, a.Name)
		}
	}
	n := len(accounts)
	if needKVM {
		row := prereqRow{Name: "groups kvm", OK: true, Detail: fmt.Sprintf("every account that used sandboxes (%d) can use /dev/kvm through the kvm group or a user ACL", n)}
		if len(noKVM) > 0 {
			row = prereqRow{Name: "groups kvm", Fix: groupFix("kvm"),
				Detail: fmt.Sprintf("%d of %d accounts that used sandboxes lack /dev/kvm read-write access (%s), so no MicroVM starts for them", len(noKVM), n, strings.Join(noKVM, ", "))}
			if s.dockerFallback() {
				row.Detail += "; they get the docker fallback"
			}
		}
		rows = append(rows, row)
	}
	why := "which the docker driver needs"
	if vm {
		why = "which MicroVM sandboxes need: their agent images are built in Docker for each account"
	}
	if len(noDocker) == 0 {
		rows = append(rows, prereqRow{Name: "groups docker", OK: true, Detail: fmt.Sprintf("every account that used sandboxes (%d) is in the docker group", n)})
	} else {
		rows = append(rows, prereqRow{Name: "groups docker", Fix: groupFix("docker"),
			Detail: fmt.Sprintf("%d of %d accounts that used sandboxes are not in the docker group (%s), %s", len(noDocker), n, strings.Join(noDocker, ", "), why)})
	}
	return rows, advisory
}

// codeDockerGroupMembers is the advisory that enrolled accounts are in the
// docker group (GAP-0498).
const codeDockerGroupMembers = "docker_group_members"

// dockerGroupAdvisory says how many of the enrolled accounts are in the
// docker group and what that means for policy privacy: membership is
// root-equivalent, so a member can read and change what root can, the
// administrator policy, the protected credentials and the services'
// environment included, and the rule that each person sees only their own
// effective policy does not hold for them. References do not help against a
// member, so the only mitigation is a small group. It counts and never names
// the accounts. "" when none is a member.
func (e *Env) dockerGroupAdvisory(members, enrolled int) string {
	if members == 0 {
		return ""
	}
	return fmt.Sprintf("%d of %d enrolled accounts are in the docker group, which is root-equivalent on this host: a member can read and "+
		"change what root can, including the administrator policy (%s), the protected credentials and the services' environment, so the "+
		"rule that each person sees only their own effective policy does not hold for them, and references keep secrets out of the policy "+
		"file but do not protect them from a member; sandboxes on Linux need the group, so the only mitigation is to add only the accounts "+
		"that run sandboxes", members, enrolled, e.Layout.ConfigPath)
}

// groupFix is the one fix of a groups row: no ready-made command per
// account, since a directory account cannot be changed with usermod.
func groupFix(group string) string {
	fix := "add the accounts that run sandboxes to the " + group + " group (a local account: usermod -aG " + group + " <name>; a directory account: " +
		"a directory group that maps to " + group + ", or its name on the " + group + " line of /etc/group), then each signs in again " +
		"(a daemon started before the change does not see the group)"
	if group == "docker" {
		fix += "; the docker group is root-equivalent, so add no administrator or service account that does not run sandboxes"
	}
	return fix
}

// userInstalls reports the OpenShell each account installed through the
// setup mode, from the install record in its home.
func (e *Env) userInstalls(ctx context.Context) []string {
	var lines []string
	for _, a := range e.sandboxOps().Accounts(ctx) {
		data, ok, err := e.readBelowHome(a, filepath.ToSlash(filepath.Join(installStateRel, openshell.TarballManifestName)), 1<<20)
		if err != nil || !ok {
			continue
		}
		var manifest openshell.InstalledRelease
		if json.Unmarshal(data, &manifest) != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: OpenShell %s", a.Name, manifest.Version))
	}
	return lines
}

// publishPrerequisites writes <ConfigDir>/openshell/prerequisites.json, the
// openshell.PrerequisitesRecord the gateway (a service account) reads through
// openshell.ReadPrerequisites: public, non-secret and root-owned.
func (e *Env) publishPrerequisites(ctx context.Context, s openshellSettings) error {
	record := openshell.PrerequisitesRecord{Version: openshell.PrerequisitesVersion, CheckedAt: e.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Install: s.Install, Driver: s.Driver, Ready: true}
	primary, fallback := e.checkOpenShellDrivers(ctx, s)
	for _, row := range primary {
		if !row.OK {
			record.Ready = false
			record.Missing = append(record.Missing, openshell.PrerequisiteMissing{Item: row.Name, Detail: row.Detail, Fix: row.Fix, Version: row.Version})
		}
	}
	if fallback != nil {
		record.Fallback = &openshell.PrerequisitesFallback{Driver: config.EnterpriseOpenShellDriverDocker, Ready: true}
		for _, row := range fallback {
			if !row.OK {
				record.Fallback.Ready = false
				record.Fallback.Missing = append(record.Fallback.Missing, openshell.PrerequisiteMissing{Item: row.Name, Detail: row.Detail, Fix: row.Fix, Version: row.Version})
			}
		}
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := e.ensureDir(e.P(e.openshellDir()), 0o755, rootOwner()); err != nil {
		return err
	}
	return e.writeFileAtomic(e.P(e.prerequisitesPath()), append(data, '\n'), 0o644, rootOwner())
}
