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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	launchdstandalone "github.com/defenseclaw/defenseclaw/packaging/launchd-standalone"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

// Enterprise OpenShell lifecycle (spec section 2.8). When openshell.enabled
// is set on a standalone managed host the lifecycle
//
//   - renders the OpenShell gateway's configuration from enterprise.openshell
//     into root-owned files under <ConfigDir>/openshell (openshell_render.go),
//   - installs and enables, for every account, the user units that run the
//     account's sandbox daemon and its OpenShell gateway, and the root-owned
//     launcher users run sandboxes with,
//   - verifies the install mode's prerequisites and reports them as status
//     rows (openshell_checks.go), and
//   - carries each account's daemon and gateway through restarts and
//     install-mode, driver or version transitions without stopping a sandbox
//     that runs (openshell_users.go).
//
// DefenseClaw never ships OpenShell: in prerequisite mode the administrator
// installs it, in setup mode each user's daemon installs NVIDIA's pinned
// release into the user's own home (openshell.TarballInstaller).
//
// In both modes the account's OpenShell gateway is DefenseClaw's own user
// unit (defenseclaw-openshell-gateway.service, or the LaunchAgent), which
// runs the gateway binary through the sandbox-openshell-exec shim on the
// rendered gateway.toml and gateway.env, and which the account's sandbox
// daemon starts and registers on demand (a prerequisite-mode account needs
// nothing of its own). The shim runs the administrator's binary from
// /usr/bin or /usr/local/bin (macOS: /usr/local/bin) in prerequisite mode
// and the account's ~/.local/bin one in setup mode. NVIDIA's own
// openshell-gateway.service is not used: it reads the account's own
// gateway.toml and sets UMask 0077, which breaks every MicroVM
// (GAP-0009, GAP-0221).
//
// The administrator's recipe for install: prerequisite (RHEL 9 with
// driver: vm; GAP-0255):
//
//  1. Install NVIDIA's openshell and openshell-gateway packages at the
//     release the build supports (0.1.3), by package on Linux. On macOS copy
//     both binaries into /usr/local/bin as root: a Homebrew prefix belongs
//     to whoever ran brew, and the shim refuses a binary an account could
//     have changed.
//  2. driver: vm only. Extract NVIDIA's openshell-driver-vm tarball into
//     /usr/local/libexec/openshell and chown -R root:root it (tar keeps the
//     builder's owner). The lifecycle renders driver_dir from the first
//     folder in openshell.AdminVMDriverDirs that holds openshell-driver-vm.
//  3. Run the lifecycle (`enterprise <os> ensure`). It needs the policies
//     folder to be root:defenseclaw 0750 and the rule pack folders to be
//     root-owned.
//  4. Do nothing per account: no drop-in for NVIDIA's unit, no
//     `openshell gateway add`, no gateway.toml of the account's own. An
//     account's first `defenseclaw sandbox run` starts its gateway unit and
//     registers it.

// Codes of the sandbox rows and conditions in a result.
const (
	codeOpenShell             = "openshell_failed"
	codeOpenShellPrerequisite = "openshell_prerequisite_missing"
	codeLauncherConflict      = "openshell_launcher_conflict"
	codeSandboxGroups         = "sandbox_user_groups"
	codeSandboxPending        = "sandbox_pending_restart"
	codeSandboxUserState      = "sandbox_user_state"
	// codeLegacySandbox: a legacy sandbox runs unprotected for an account
	// (describeLegacySandboxes).
	codeLegacySandbox = "sandbox_legacy_unprotected"
	// codeDriverFallback: the MicroVM driver can't run on the host, users
	// get the docker fallback (or the fallback itself lacks something).
	codeDriverFallback = "openshell_driver_fallback"

	// sandboxRowKind marks the service rows that report the sandbox
	// subsystem (the JSON services list and the text status print them with
	// the units).
	sandboxRowKind = "sandbox"

	openshellStateFile = "openshell-state.json"
)

// Names of the sandbox user units.
const (
	userUnitSandboxSocket  = "defenseclaw-sandbox.socket"
	userUnitSandboxService = "defenseclaw-sandbox.service"
	userUnitGatewayService = "defenseclaw-openshell-gateway.service"

	labelSandbox          = openshell.SandboxAgentBase
	labelOpenShellGateway = openshell.GatewayAgentBase
)

// openshellSettings are the sandbox settings the lifecycle derives from the
// validated administrator config.
type openshellSettings struct {
	// Enabled is openshell.enabled.
	Enabled bool
	// Install is prerequisite or setup; Driver docker, vm or auto (auto on
	// Linux only: the per-user KVM probe picks vm or docker at sandbox
	// start).
	Install, Driver string
	// Fallback is the host's docker fallback of the MicroVM driver
	// (enterprise.openshell.driver_fallback tightened by openshell.admin):
	// docker, none, or "" where none applies (macOS, the docker driver).
	Fallback string
	// Version is enterprise.openshell.version: an exact version, a range or
	// "" (any release the DefenseClaw build supports). In setup mode an
	// exact pin older than openshell.SupportedMin is raised to the release
	// this build installs, and RaisedFrom keeps the pin
	// (openshell.ManagedSetupPin).
	Version, RaisedFrom string
	GatewayPort         int
	E2fsprogsDir        string
	// TelemetryAllowed is openshell.admin.allow_upstream_telemetry.
	TelemetryAllowed bool
}

// openshellSettingsOf applies the defaults: prerequisite mode, the macOS
// MicroVM and the Linux docker driver, and the gateway port 17670.
func openshellSettingsOf(goos string, cfg *config.Config) openshellSettings {
	var s openshellSettings
	if cfg == nil {
		return s
	}
	o := cfg.Enterprise.OpenShell
	s.Enabled = cfg.OpenShell.Enabled
	s.Install = strings.ToLower(strings.TrimSpace(o.Install))
	if s.Install == "" {
		s.Install = config.EnterpriseOpenShellInstallPrerequisite
	}
	s.Driver = o.SandboxDriver(goos)
	s.Fallback = o.SandboxDriverFallback(goos, cfg.OpenShell.Admin)
	s.Version = strings.TrimSpace(o.Version)
	if v, raised := openshell.ManagedSetupPin(s.Install == config.EnterpriseOpenShellInstallSetup, s.Version); raised {
		s.Version, s.RaisedFrom = v, s.Version
	}
	s.GatewayPort = o.GatewayPort
	if s.GatewayPort == 0 {
		s.GatewayPort = config.DefaultEnterpriseOpenShellGatewayPort
	}
	s.E2fsprogsDir = o.E2fsprogsDir
	s.TelemetryAllowed = cfg.OpenShell.Admin.AllowUpstreamTelemetry != nil && *cfg.OpenShell.Admin.AllowUpstreamTelemetry
	return s
}

// rendered is the gateway configuration these settings render to. driverDir
// is where the administrator's OpenShell keeps its MicroVM driver ("" keeps
// the gateway's default search path).
func (s openshellSettings) rendered(driverDir string) openshell.RenderedGateway {
	return openshell.RenderedGateway{
		BindAddress:      "127.0.0.1:" + strconv.Itoa(s.GatewayPort),
		ComputeDriver:    openshell.ComputeDriver(s.computeDriver()),
		DriverDir:        driverDir,
		TelemetryEnabled: s.TelemetryAllowed,
	}
}

// computeDriver is the driver gateway.toml renders: vm for auto (the
// probe's docker answer gets the fallback file).
func (s openshellSettings) computeDriver() string {
	if s.Driver == config.EnterpriseOpenShellDriverAuto {
		return config.EnterpriseOpenShellDriverVM
	}
	return s.Driver
}

// wantsVM reports whether the settings want the MicroVM driver.
func (s openshellSettings) wantsVM() bool {
	return s.computeDriver() == config.EnterpriseOpenShellDriverVM
}

// dockerFallback reports whether a user whose KVM probe fails gets the
// docker driver (Linux, driver vm or auto, driver_fallback docker).
func (s openshellSettings) dockerFallback() bool {
	return s.wantsVM() && s.Fallback == config.EnterpriseOpenShellFallbackDocker
}

// fallbackSettings are the settings the docker fallback runs with: the
// same install mode, version and port, on docker.
func (s openshellSettings) fallbackSettings() openshellSettings {
	f := s
	f.Driver, f.Fallback = config.EnterpriseOpenShellDriverDocker, ""
	return f
}

// Paths of the sandbox pieces on this host.
func (e *Env) openshellDir() string { return filepath.Join(e.Layout.ConfigDir, "openshell") }

// packageOwnsOpenShellDir reports whether the package manager owns
// openshellDir: the rpm and deb ship it (.goreleaser.yaml) so an erase leaves
// no empty one behind. The lifecycle writes into it but never removes it there;
// an ensure with sandboxes off removed the empty directory the package had
// just installed, and the package database then listed a directory the host
// no longer had.
func (e *Env) packageOwnsOpenShellDir(channel string) bool {
	return e.GOOS == "linux" && channel == ChannelPackage
}
func (e *Env) renderedTOMLPath() string {
	return filepath.Join(e.openshellDir(), openshell.GatewayTOMLFile)
}
func (e *Env) renderedFallbackTOMLPath() string {
	return filepath.Join(e.openshellDir(), openshell.GatewayFallbackTOMLFile)
}
func (e *Env) renderedBridgeTOMLPath() string {
	return filepath.Join(e.openshellDir(), openshell.GatewayDefaultNamespaceTOMLFile)
}
func (e *Env) renderedEnvPath() string {
	return filepath.Join(e.openshellDir(), openshell.GatewayEnvFile)
}
func (e *Env) prerequisitesPath() string {
	return filepath.Join(e.openshellDir(), openshell.PrerequisitesFile)
}
func (e *Env) openshellStatePath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), openshellStateFile)
}

// launcherPath is the root-owned symlink users run sandboxes with.
func (e *Env) launcherPath() string {
	if e.GOOS == "darwin" {
		return "/usr/local/bin/defenseclaw"
	}
	return "/usr/bin/defenseclaw"
}

// foreignLauncher reports whether the launcher path holds something that is
// not a symlink, such as the defenseclaw of a Python install. The lifecycle
// never replaces it: the link is skipped, and the sandbox rows say so
// (openshell_launcher_conflict).
func (e *Env) foreignLauncher() bool {
	info, err := os.Lstat(e.P(e.launcherPath()))
	return err == nil && info.Mode()&os.ModeSymlink == 0
}

// launcherTarget is what the launcher points at: the gateway binary, which
// offers only the sandbox tree under the name defenseclaw.
func (e *Env) launcherTarget() string { return filepath.Join(e.Layout.BinDir, binGateway) }

// userUnit is one of the user-level units of the sandbox subsystem.
type userUnit struct {
	// Name is the unit file name (systemd) or label (launchd).
	Name string
	// Source is the file name in the embedded unit assets.
	Source string
}

// userUnits are the sandbox user units. On macOS each label carries the tag
// of the gateway the deployment runs (openshell.LaunchAgentLabel), so an
// upgrade installs jobs of a label macOS has not decided on (GAP-0206).
func (e *Env) userUnits() []userUnit {
	if e.GOOS == "darwin" {
		digest := e.launchAgentDigest()
		return []userUnit{
			{Name: openshell.LaunchAgentLabel(labelSandbox, digest), Source: labelSandbox + ".plist"},
			{Name: openshell.LaunchAgentLabel(labelOpenShellGateway, digest), Source: labelOpenShellGateway + ".plist"},
		}
	}
	return []userUnit{
		{Name: userUnitSandboxSocket, Source: userUnitSandboxSocket},
		{Name: userUnitSandboxService, Source: userUnitSandboxService},
		{Name: userUnitGatewayService, Source: userUnitGatewayService},
	}
}

// userUnitPath is where a user unit's definition is installed.
func (e *Env) userUnitPath(u userUnit, channel string) string {
	if e.GOOS == "darwin" {
		return filepath.Join("/Library/LaunchAgents", u.Name+".plist")
	}
	if channel == ChannelPackage {
		return filepath.Join("/usr/lib/systemd/user", u.Name)
	}
	return filepath.Join("/etc/systemd/user", u.Name)
}

// userUnitBytes reads a unit's embedded definition: the user units under
// packaging/systemd/user and the LaunchAgents under
// packaging/launchd-standalone/agents, which the system units' embed globs do
// not carry (UserUnitSource overrides it in tests). On a managed Mac, a
// verified packaged gateway copy gets a content-addressed program path, and
// the plist names the unit's tagged label.
func (e *Env) userUnitBytes(u userUnit) ([]byte, error) {
	if e.UserUnitSource != nil {
		data, err := e.UserUnitSource(u.Source)
		if err != nil || e.GOOS != "darwin" {
			return data, err
		}
		return withLaunchAgentLabel(data, u), nil
	}
	if e.GOOS == "darwin" {
		data, err := launchdstandalone.ReadAgentPlist(strings.TrimSuffix(u.Source, ".plist"))
		if err != nil {
			return nil, err
		}
		gateway := filepath.Join(e.Layout.BinDir, binGateway)
		program, err := e.launchAgentProgram()
		if err != nil {
			return nil, err
		}
		return withLaunchAgentLabel([]byte(strings.Replace(string(data), gateway, program, 1)), u), nil
	}
	return systemdunits.ReadUserUnit(u.Source)
}

// withLaunchAgentLabel names u's label in the Label of its plist, which
// the embedded asset gives as the base label.
func withLaunchAgentLabel(data []byte, u userUnit) []byte {
	base := strings.TrimSuffix(u.Source, ".plist")
	return []byte(strings.Replace(string(data), "<string>"+base+"</string>", "<string>"+u.Name+"</string>", 1))
}

// launchAgentDigest is the SHA-256 of the gateway the LaunchAgents run: the
// one the plan being applied installs, else the installed one. "" when there
// is none yet, which keeps the bare base labels.
func (e *Env) launchAgentDigest() string {
	if e.agentDigest != "" {
		return e.agentDigest
	}
	digest, _ := sha256File(e.P(filepath.Join(e.Layout.BinDir, binGateway)))
	return digest
}

// launchAgentLabel is the installed job label of base: the one whose plist
// is in /Library/LaunchAgents (openshell.FindLaunchAgent).
func (e *Env) launchAgentLabel(base string) string {
	label, _ := openshell.FindLaunchAgent(e.P(openshell.LaunchAgentsDir), base)
	return label
}

// strayLaunchAgents are the plists of DefenseClaw's sandbox LaunchAgents in
// /Library/LaunchAgents that want does not name: those of an earlier label,
// which 1.0.0 to 1.0.3 and every earlier package installed (GAP-0206).
func (e *Env) strayLaunchAgents(want map[string]bool) []string {
	entries, _ := os.ReadDir(e.P(openshell.LaunchAgentsDir))
	var stray []string
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".plist")
		if !ok || !openshell.IsLaunchAgentLabel(labelSandbox, name) && !openshell.IsLaunchAgentLabel(labelOpenShellGateway, name) {
			continue
		}
		path := filepath.Join(openshell.LaunchAgentsDir, entry.Name())
		if !want[path] {
			stray = append(stray, path)
		}
	}
	return stray
}

// launchAgentProgram is the gateway file both macOS LaunchAgents execute: the
// package's content-addressed copy of the installed gateway when it is there,
// else the gateway itself. A copy that is not a regular file or differs from
// the gateway is refused.
func (e *Env) launchAgentProgram() (string, error) {
	gateway := filepath.Join(e.Layout.BinDir, binGateway)
	digest, err := sha256File(e.P(gateway))
	if os.IsNotExist(err) {
		return gateway, nil // A fresh non-package payload has not installed the gateway yet.
	}
	if err != nil {
		return "", fmt.Errorf("identify the LaunchAgent gateway: %w", err)
	}
	program := filepath.Join(e.Layout.BinDir, "launch-agents", digest, binGateway)
	info, err := os.Lstat(e.P(program))
	if os.IsNotExist(err) {
		return gateway, nil // Older and non-package installations use the canonical path.
	}
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("the packaged LaunchAgent gateway is not a regular file: %s", program)
	}
	copyDigest, err := sha256File(e.P(program))
	if err != nil || copyDigest != digest {
		return "", fmt.Errorf("the packaged LaunchAgent gateway differs from %s", gateway)
	}
	return program, nil
}

// wantsLinkFor is the symlink that enables the sandbox socket for every
// account (what `systemctl --global enable` writes): the user manager of any
// account that signs in starts the socket, which holds only the account's
// own Unix socket (spec D3). "" off Linux, where the launcher bootstraps the
// agent on demand.
func (e *Env) wantsLinkFor(channel string, socket []byte) (link, target string) {
	if e.GOOS != "linux" {
		return "", ""
	}
	wantedBy := "sockets.target"
	for _, line := range strings.Split(string(socket), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "WantedBy="); ok {
			if fields := strings.Fields(v); len(fields) > 0 {
				wantedBy = fields[0]
			}
		}
	}
	unit := userUnit{Name: userUnitSandboxSocket}
	return filepath.Join("/etc/systemd/user", wantedBy+".wants", userUnitSandboxSocket), e.userUnitPath(unit, channel)
}

// desiredLink is a symlink the lifecycle owns.
type desiredLink struct {
	Path, Target string
	// Kind is "launcher" or "enable".
	Kind string
}

// openshellPlan is what one apply installs for the sandbox subsystem.
type openshellPlan struct {
	settings openshellSettings
	rendered openshell.RenderedGateway
	files    []desiredFile
	dirs     []desiredDir
	links    []desiredLink
	// staleLinks are links the lifecycle owns that the plan no longer wants.
	staleLinks []string
	// digest is the digest of the rendered configuration.
	digest string
	// daemonInputs identifies what a running daemon was started on: the unit
	// definitions, the gateway binary and the rendered configuration.
	daemonInputs string
	// defaultNamespaceBridge renders the 1.0.1 upgrade bridge
	// (openshell.GatewayDefaultNamespaceTOMLFile, dockerBridgeHolds). 1.0.1
	// upgrade bridge, remove when 1.0.1 is out of support.
	defaultNamespaceBridge bool
}

// planOpenShell adds the sandbox subsystem to the plan: its files, folders
// and links when openshell.enabled is set, and the links to remove when it
// is not. Files the previous deployment wrote that are no longer wanted are
// removed by the plan's stale list.
func (l *lifecycle) planOpenShell(p *plan) error {
	env := l.env
	if p.payload != nil {
		env.agentDigest = p.payload.Digests[binGateway]
	}
	settings := openshellSettingsOf(env.GOOS, p.config.Loaded)
	op := &openshellPlan{settings: settings}
	op.defaultNamespaceBridge = dockerBridgeHolds(env.GOOS, settings, l.openShellAppliedForPlan())
	p.openshell = op
	l.osPlan = op

	managedLinks := env.ownedLinks(p.channel)
	if !settings.Enabled {
		if env.GOOS == "darwin" && p.channel == ChannelPackage {
			return env.planPackagedMacOSSandbox(p, op)
		}
		for _, link := range managedLinks {
			if env.linkIsOurs(link) {
				op.staleLinks = append(op.staleLinks, link.Path)
			}
		}
		return nil
	}

	// A setup pin this build cannot install would surface only at a user's
	// first sandbox run: refuse it here, before anything changes (GAP-0236).
	if settings.Install == config.EnterpriseOpenShellInstallSetup && openshell.TarballPins[settings.Version] == nil {
		return fmt.Errorf("enterprise.openshell.version %q is not a release this DefenseClaw build can install in setup mode; set it to one of: %s",
			settings.Version, strings.Join(openshell.PinnedTarballReleases(), ", "))
	}
	root := rootOwner()
	op.dirs = append(op.dirs, desiredDir{Path: env.openshellDir(), Mode: 0o755, Owner: root})
	if err := env.renderGatewayFiles(op); err != nil {
		return err
	}
	units, socket, err := env.renderUserUnits(p, op)
	if err != nil {
		return err
	}

	// The enable link, and the launcher wherever no package manager owns it
	// (the Linux package installs its own).
	for _, link := range env.desiredLinks(p.channel, socket) {
		if link.Kind == "launcher" && env.GOOS == "linux" && p.channel == ChannelPackage {
			continue
		}
		if link.Kind == "launcher" && env.foreignLauncher() {
			// Not part of the transaction: it is not snapshotted, not
			// replaced and cannot fail the apply. describeOpenShell reports it.
			continue
		}
		op.links = append(op.links, link)
		if link.Kind == "enable" {
			op.dirs = append(op.dirs, desiredDir{Path: filepath.Dir(link.Path), Mode: 0o755, Owner: root, External: true})
		}
	}
	op.daemonInputs = daemonInputsDigest(units, p.payload, op.digest)
	p.files = append(p.files, op.files...)
	p.dirs = append(p.dirs, op.dirs...)
	// Links the plan no longer wants (a changed wants target).
	wanted := map[string]bool{}
	for _, link := range op.links {
		wanted[link.Path] = true
	}
	for _, link := range managedLinks {
		if !wanted[link.Path] && env.linkIsOurs(link) {
			op.staleLinks = append(op.staleLinks, link.Path)
		}
	}
	return nil
}

// planPackagedMacOSSandbox keeps, with the sandbox subsystem off, what the
// macOS pkg installs whatever openshell.enabled says
// (scripts/build-macos-enterprise-pkg.sh): the launcher and the launch
// agents as the pkg wrote them. A pkg has no remover, so they are part of the
// deployment: ensure keeps or restores them, and uninstall removes them with
// the deployment record and the owned links. A launcher path that holds a
// foreign file is left alone, as with the subsystem on.
func (e *Env) planPackagedMacOSSandbox(p *plan, op *openshellPlan) error {
	root := rootOwner()
	for _, u := range e.userUnits() {
		data, err := e.userUnitBytes(u)
		if err != nil {
			return fmt.Errorf("this build carries no %s launch agent (%v): reinstall the DefenseClaw enterprise package", u.Name, err)
		}
		p.files = append(p.files, desiredFile{Path: e.userUnitPath(u, p.channel), Data: data, SHA: sha256Bytes(data), Mode: 0o644, Owner: root, Kind: "user-unit"})
	}
	if !e.foreignLauncher() {
		op.links = append(op.links, desiredLink{Path: e.launcherPath(), Target: e.launcherTarget(), Kind: "launcher"})
	}
	return nil
}

// daemonInputsDigest is what a running sandbox daemon depends on.
func daemonInputsDigest(units map[string]string, pay *payload, rendered string) string {
	var b strings.Builder
	for _, path := range sortedKeys(units) {
		fmt.Fprintf(&b, "%s=%s\n", path, units[path])
	}
	if pay != nil {
		fmt.Fprintf(&b, "gateway=%s\n", pay.Digests[binGateway])
	}
	fmt.Fprintf(&b, "rendered=%s\n", rendered)
	return sha256Bytes([]byte(b.String()))
}

// ownedLinks are the links the lifecycle can own on this host: the wants
// link of every wanted-by target the unit could name, and the launcher.
func (e *Env) ownedLinks(channel string) []desiredLink {
	var links []desiredLink
	if e.GOOS == "linux" {
		unit := userUnit{Name: userUnitSandboxSocket}
		target := e.userUnitPath(unit, channel)
		for _, wantedBy := range []string{"sockets.target", "default.target"} {
			links = append(links, desiredLink{Path: filepath.Join("/etc/systemd/user", wantedBy+".wants", userUnitSandboxSocket), Target: target, Kind: "enable"})
		}
	}
	if e.GOOS == "darwin" || channel != ChannelPackage {
		links = append(links, desiredLink{Path: e.launcherPath(), Target: e.launcherTarget(), Kind: "launcher"})
	}
	return links
}

// linkIsOurs reports whether the link at link.Path exists and points where a
// link of the lifecycle would: nothing else is ever removed.
func (e *Env) linkIsOurs(link desiredLink) bool {
	target, err := os.Readlink(e.P(link.Path))
	if err != nil {
		return false
	}
	if link.Kind == "launcher" {
		return target == link.Target
	}
	// An enable link points at either channel's definition.
	unit := userUnit{Name: userUnitSandboxSocket}
	return target == e.userUnitPath(unit, ChannelPackage) || target == e.userUnitPath(unit, ChannelPayload)
}

// applyOpenShellLinks creates the planned links and removes the stale ones,
// inside the transaction (snapshotLinks recorded them first).
func (l *lifecycle) applyOpenShellLinks(p *plan) error {
	env := l.env
	if p.openshell == nil {
		return nil
	}
	for _, link := range p.openshell.links {
		changed, err := env.ensureSymlink(link.Path, link.Target)
		if err != nil {
			return fmt.Errorf("%s: %w", link.Path, err)
		}
		if changed {
			l.noteChange("pointed %s at %s", link.Path, link.Target)
		}
	}
	for _, path := range p.openshell.staleLinks {
		if err := removeFile(env.P(path)); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		l.noteChange("removed %s, which the deployment no longer uses", path)
		_ = removeDirIfEmpty(env.P(filepath.Dir(path)))
	}
	if !p.openshell.settings.Enabled {
		// What the lifecycle derived while the subsystem was on goes with it.
		_ = removeFile(env.P(env.prerequisitesPath()))
		if !env.packageOwnsOpenShellDir(p.channel) {
			_ = removeDirIfEmpty(env.P(env.openshellDir()))
		}
	}
	return nil
}

// openshellLinkPaths are the links a transaction may change, for the snapshot.
func (p *plan) openshellLinkPaths() []string {
	if p.openshell == nil {
		return nil
	}
	var paths []string
	for _, link := range p.openshell.links {
		paths = append(paths, link.Path)
	}
	return append(paths, p.openshell.staleLinks...)
}

// ensureSymlink makes path a symlink to target, atomically replacing a
// different symlink. Anything that is not a symlink there is never replaced.
func (e *Env) ensureSymlink(path, target string) (changed bool, err error) {
	full := e.P(path)
	if current, err := os.Readlink(full); err == nil && current == target {
		return false, nil
	} else if err != nil {
		if info, lerr := os.Lstat(full); lerr == nil {
			if info.Mode()&os.ModeSymlink == 0 {
				return false, fmt.Errorf("%s exists and is not a symlink; remove it so the lifecycle can point it at %s", path, target)
			}
		} else if !errors.Is(lerr, os.ErrNotExist) {
			return false, lerr
		}
	}
	if err := mkdirParents(filepath.Dir(full)); err != nil {
		return false, err
	}
	tmp := fmt.Sprintf("%s.dc-%d", full, os.Getpid())
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, full); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	syncDir(filepath.Dir(full))
	return true, nil
}

// systemDriverDir is the directory holding a trusted openshell-driver-vm, or
// "": the rendered gateway configuration never points at a driver another
// account can change.
func (e *Env) systemDriverDir() string {
	dir, _ := e.systemDriver()
	return dir
}

// systemDriver is systemDriverDir with the candidates that exist but fail
// the managed trust check. It is openshell.AdminVMDriver, the check a
// managed user's `sandbox doctor` runs too (GAP-0481), on this filesystem.
func (e *Env) systemDriver() (dir string, refused []string) {
	found, refused := openshell.AdminVMDriver(e.GOOS, func(p string) bool { return openshell.ExecutableVMDriver(e.P(p)) },
		func(p string) error { return e.Trust(e.P(p), TrustAdminFile) })
	if found == "" {
		return "", refused
	}
	return filepath.Dir(found), refused
}

// openshellState is the root-only record of what the lifecycle last applied
// to the sandbox subsystem and of the per-user changes waiting for sandboxes
// to stop.
type openshellState struct {
	Version         int                `json:"version"`
	Applied         *openshellApplied  `json:"applied,omitempty"`
	Pending         map[string]pending `json:"pending,omitempty"`
	GatewayIdentity string             `json:"gateway_identity,omitempty"`
}

// openshellApplied is the sandbox configuration the last committed
// transaction applied.
type openshellApplied struct {
	Enabled      bool   `json:"enabled"`
	Install      string `json:"install"`
	Driver       string `json:"driver"`
	Fallback     string `json:"driver_fallback,omitempty"`
	Version      string `json:"version,omitempty"`
	GatewayPort  int    `json:"gateway_port"`
	Rendered     string `json:"rendered,omitempty"`
	DaemonInputs string `json:"daemon_inputs,omitempty"`
	// E2fsprogsDir is enterprise.openshell.e2fsprogs_dir.
	E2fsprogsDir string `json:"e2fsprogs_dir,omitempty"`
	// DockerNamespace is the OpenShell sandbox namespace (sandbox_label) of
	// the docker gateways the render starts: the docker driver and the
	// docker fallback of the MicroVM driver; "" when the render has none. A
	// record written before the render named one (1.0.1, the 1.0.2 release
	// candidates) has none either: its docker gateways ran in OpenShell's
	// default namespace, so the upgrade from it keeps the 1.0.1 upgrade
	// bridge (dockerBridgeHolds).
	DockerNamespace string `json:"docker_namespace,omitempty"`
	// DefaultNamespaceBridge records that the render carries the 1.0.1
	// upgrade bridge (openshell.GatewayDefaultNamespaceTOMLFile), so it
	// stays on the next runs. 1.0.1 upgrade bridge, remove when 1.0.1 is out
	// of support.
	DefaultNamespaceBridge bool `json:"default_namespace_bridge,omitempty"`
}

func appliedOf(op *openshellPlan) *openshellApplied {
	if op == nil {
		return nil
	}
	s := op.settings
	a := &openshellApplied{Enabled: s.Enabled, Install: s.Install, Driver: s.Driver, Fallback: s.Fallback, Version: s.Version,
		GatewayPort: s.GatewayPort, Rendered: op.digest, DaemonInputs: op.daemonInputs, E2fsprogsDir: s.E2fsprogsDir,
		DefaultNamespaceBridge: op.defaultNamespaceBridge}
	if a.usesDocker() {
		a.DockerNamespace = openshell.ManagedDockerNamespace
	}
	return a
}

// usesDocker reports whether the applied setup starts docker gateways: the
// docker driver, or the MicroVM driver with the docker fallback.
func (a *openshellApplied) usesDocker() bool {
	return a.Driver == config.EnterpriseOpenShellDriverDocker || a.Fallback == config.EnterpriseOpenShellFallbackDocker
}

// dockerBridgeHolds reports whether a render on settings s, after the
// applied record prev, carries the 1.0.1 upgrade bridge (GAP-0587): prev is
// a docker record of 1.0.1 (or of the 1.0.2 release candidates 1 to 3),
// which names no docker namespace, or already carries the bridge, and s
// still starts docker gateways on Linux. 1.0.1's managed docker gateways had
// no sandbox_label, so the sandboxes their accounts kept are in OpenShell's
// default namespace, which the managed namespace's gateway does not list.
// Moving such an account was a switch that stranded them (their unpulled
// work was lost); with the bridge its gateway stays in the default namespace
// until it keeps no sandbox there (the exec shim decides per account, at
// each gateway start), so nothing is switched and the namespace is no part
// of switchKey. Sandboxes turned off keep the bridge for when they are
// turned on again; a setup without docker gateways ends it (a driver switch
// says what it does to the sandboxes made before). 1.0.1 upgrade bridge,
// remove when 1.0.1 is out of support.
func dockerBridgeHolds(goos string, s openshellSettings, prev *openshellApplied) bool {
	if goos != "linux" || prev == nil {
		return false
	}
	if bridged := prev.DefaultNamespaceBridge || (prev.usesDocker() && prev.DockerNamespace == ""); !bridged {
		return false
	}
	return !s.Enabled || s.Driver == config.EnterpriseOpenShellDriverDocker || s.dockerFallback()
}

// switchKey changes when the account's OpenShell has to be replaced rather
// than just restarted.
func (a *openshellApplied) switchKey() string {
	if a == nil || !a.Enabled {
		return ""
	}
	version := a.Version
	if a.Install != config.EnterpriseOpenShellInstallSetup {
		// In prerequisite mode the pin checks the administrator's OpenShell
		// (a verify row); changing it replaces nothing in an account
		// (GAP-0244).
		version = ""
	}
	key := strings.Join([]string{a.Install, a.Driver, version, strconv.Itoa(a.GatewayPort)}, "|")
	if a.Fallback != "" {
		// A changed fallback changes which rendered file a user's
		// gateway starts with.
		key += "|" + a.Fallback
	}
	return key
}

// pending is one account's change that waits for its sandboxes to stop.
type pending struct {
	User string `json:"user"`
	UID  int    `json:"uid"`
	Home string `json:"home"`
	// Kind is "restart" (the daemon runs outdated inputs), "switch" (the
	// install mode, driver, version or port changed) or "stop" (sandboxes
	// were turned off).
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	Since  string `json:"since"`
	// From is the applied configuration a switch leaves.
	From *openshellApplied `json:"from,omitempty"`
	// Sandboxes is how many ran when the change was last tried.
	Sandboxes int `json:"sandboxes"`
}

func (e *Env) loadOpenShellState() *openshellState {
	state := &openshellState{Version: 1, Pending: map[string]pending{}}
	data, err := readBounded(e.openshellStatePath(), maxInputBytes)
	if err != nil {
		return state
	}
	var loaded openshellState
	if json.Unmarshal(data, &loaded) != nil || loaded.Version != 1 {
		return state
	}
	if loaded.Pending == nil {
		loaded.Pending = map[string]pending{}
	}
	return &loaded
}

func (e *Env) saveOpenShellState(state *openshellState) error {
	if state.Applied == nil && len(state.Pending) == 0 {
		return removeFile(e.openshellStatePath())
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return e.writeFileAtomic(e.openshellStatePath(), append(data, '\n'), 0o600, rootOwner())
}

// sortedPending lists the pending changes by user name.
func (s *openshellState) sortedPending() []pending {
	out := make([]pending, 0, len(s.Pending))
	for _, entry := range s.Pending {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// verifyOpenShell is the part of verify that fails the deployment: the
// sandbox units and links the transaction installed. What the host lacks for
// sandboxes to run is a warning (describeOpenShell). Inside a transaction it
// checks the plan being applied; otherwise what the last commit applied.
func (l *lifecycle) verifyOpenShell(record *Deployment) []string {
	env := l.env
	if !l.openshellExpected() {
		return nil
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	var socket []byte
	for _, u := range env.userUnits() {
		path := env.userUnitPath(u, record.Channel)
		want, err := env.userUnitBytes(u)
		if err != nil {
			add("this build carries no %s unit (%v)", u.Name, err)
			continue
		}
		if u.Name == userUnitSandboxSocket {
			socket = want
		}
		got, gerr := sha256File(env.P(path))
		switch {
		case gerr != nil:
			add("%s is missing, so users cannot run sandboxes; run `%s`", path, env.lifecycleCommand(ActionRepair))
		case record.Channel == ChannelPackage && env.GOOS == "linux" && got != sha256Bytes(want):
			add("%s does not match this build; reinstall the package", path)
		}
	}
	for _, link := range env.desiredLinks(record.Channel, socket) {
		if link.Kind == "launcher" && env.foreignLauncher() {
			continue // a sandbox row and a warning, not a failure of the deployment
		}
		target, err := os.Readlink(env.P(link.Path))
		switch {
		case err != nil && link.Kind == "launcher" && record.Channel == ChannelPackage && env.GOOS == "linux":
			add("%s is missing, so users cannot run `defenseclaw sandbox`; reinstall the package", link.Path)
		case err != nil:
			add("%s is missing; run `%s`", link.Path, env.lifecycleCommand(ActionRepair))
		case target != link.Target:
			add("%s points at %s, not at %s; run `%s`", link.Path, target, link.Target, env.lifecycleCommand(ActionRepair))
		}
	}
	return problems
}

// openshellExpected reports whether the deployment is meant to run the
// sandbox subsystem: the plan of the running transaction, else the last
// commit.
func (l *lifecycle) openshellExpected() bool {
	if l.osPlan != nil {
		return l.osPlan.settings.Enabled
	}
	applied := l.env.loadOpenShellState().Applied
	return applied != nil && applied.Enabled
}

// desiredLinks are the links a deployment of channel carries when the
// sandbox subsystem is on: the enable link the socket unit asks for (Linux)
// and the launcher.
func (e *Env) desiredLinks(channel string, socket []byte) []desiredLink {
	var links []desiredLink
	if link, target := e.wantsLinkFor(channel, socket); link != "" {
		links = append(links, desiredLink{Path: link, Target: target, Kind: "enable"})
	}
	return append(links, desiredLink{Path: e.launcherPath(), Target: e.launcherTarget(), Kind: "launcher"})
}

// removeOpenShellFiles removes, on uninstall, the links the lifecycle made
// and the folders its user units left empty, and removes the lifecycle's own
// sandbox records. When sandboxes stay, their applied setup record moves to a
// root-only kept name for the next ensure; a rerun of a failed uninstall keeps
// the record moved by the first run. The unit files and rendered config are in
// the deployment record and go with it. A link someone else made is left alone.
func (l *lifecycle) removeOpenShellFiles(record *Deployment) {
	env := l.env
	channel := ChannelPayload
	if record != nil {
		channel = record.Channel
	}
	for _, link := range env.ownedLinks(channel) {
		if !env.linkIsOurs(link) {
			continue
		}
		if err := removeFile(env.P(link.Path)); err != nil {
			l.result.AddWarning(codeOpenShell, fmt.Sprintf("could not remove %s: %v", link.Path, err))
			continue
		}
		_ = removeDirIfEmpty(env.P(filepath.Dir(link.Path)))
	}
	if env.GOOS == "linux" {
		for _, u := range env.userUnits() {
			_ = removeDirIfEmpty(env.P(filepath.Join("/etc/systemd/user", u.Name+".d")))
		}
	}
	kept, err := env.removeOpenShellMachineState(channel, !l.opts.Purge && len(l.sandboxesKept) > 0)
	l.openshellRecordKept = kept
	if err != nil {
		// The record only helps the next activation report a changed setup;
		// a problem with it must not stop an uninstall or a package removal.
		l.result.AddWarning(codeOpenShell, err.Error())
	}
}
