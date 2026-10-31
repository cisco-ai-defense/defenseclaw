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

package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// Whether a sandbox can run for one account on this host, as the managed
// gateway judges it for the require-sandbox gate (require_sandbox.go): a
// host run of a required agent is refused with a paste-ready `sandbox run`
// command where a sandbox can run, and with the "not available" text (or an
// alert, under when_unavailable: alert) where it can't. The gateway runs as
// a service account, so it judges the caller's account by the peer uid: its
// groups and the modes of the devices the compute driver needs, never the
// gateway's own access; and the host by the OpenShell prerequisites the
// lifecycle last found.
//
// On Linux the MicroVM driver (enterprise.openshell.driver vm or auto)
// falls back to docker where KVM does not work for the account, unless the
// account's driver_fallback is none (owner decision 2026-10-10): the
// fallback needs the same docker access as the docker driver, and the answer
// names the driver and the reason. The user's own daemon probes again at
// sandbox start as the user, and that probe decides the sandbox's driver.

// sandboxAvailability is the probe's answer for one account. Why is the
// caller-facing reason sandboxes can't run, for
// sandboxapi.HostRunUnavailable; it names only the caller's own facts.
// Code is Why's registered reason code for the sandbox telemetry. Driver
// and DriverReason are the compute driver a sandbox would get and why
// (openshell.DriverReason*), when Available. Provisional marks an answer
// that rests on groups that couldn't be looked up (a directory outage): a
// sandbox may run, as the account's own daemon probes the devices as the
// account at sandbox start, and the answer is not cached (GAP-0507).
type sandboxAvailability struct {
	Available    bool
	Why          string
	Code         string
	Driver       string
	DriverReason string
	Provisional  bool
}

// Reasons a sandbox can't run for an account.
const (
	sandboxUnavailableWindows       = "sandboxes don't run on Windows"
	sandboxUnavailablePlatform      = "OpenShell sandboxes don't run on this operating system"
	sandboxUnavailableAppleSilicon  = "OpenShell sandboxes need a Mac with Apple silicon"
	sandboxUnavailableOff           = "sandboxes are turned off on this computer"
	sandboxUnavailableRoot          = "sandboxes don't run as root"
	sandboxUnavailableAccount       = "your account could not be verified"
	sandboxUnavailableNoDocker      = "Docker is not running"
	sandboxUnavailableDockerAccess  = "the Docker socket isn't read-write for your account"
	sandboxUnavailableUnknownDriver = "the organization's sandbox driver isn't supported here"
	// KVM that does not work for the account is sandboxVMRequired's (codes
	// no_kvm, no_kvm_access) under driver_fallback: none; otherwise the
	// docker fallback runs.
	// The OpenShell prerequisites the lifecycle records (prerequisites.json).
	sandboxUnavailableNotSetUp = "OpenShell is not set up on this computer"
	// sandboxUnavailableSetupChanging: the record is of another driver or
	// install mode than the configured one, which the lifecycle has not
	// prepared yet (an administrator's switch, #1203).
	sandboxUnavailableSetupChanging     = sandboxrelay.UnavailableSetupChanging
	sandboxUnavailableNoOpenShell       = "OpenShell is not installed"
	sandboxUnavailableDockerMissing     = "Docker is not installed"
	sandboxUnavailablePrerequisiteOther = "a sandbox prerequisite is missing on this computer"
)

// sandboxUnavailableCodes are the registered reason codes
// (log.sandbox.host_run_unavailable) of the reasons; a reason without one
// is a missing prerequisite.
var sandboxUnavailableCodes = map[string]string{
	sandboxUnavailableWindows:       "os_unsupported",
	sandboxUnavailablePlatform:      "os_unsupported",
	sandboxUnavailableAppleSilicon:  "os_unsupported",
	sandboxUnavailableOff:           "sandboxes_off",
	sandboxUnavailableRoot:          "root_account",
	sandboxUnavailableAccount:       "account_unverified",
	sandboxUnavailableNoDocker:      "no_docker",
	sandboxUnavailableDockerAccess:  "no_docker_access",
	sandboxUnavailableUnknownDriver: "driver_unsupported",
}

// The codes of an account outside the group a device grants read-write
// access to; the reason names the group (sandboxNotInGroup).
const (
	sandboxCodeNoDockerGroup = "no_docker_group"
	sandboxCodeNoKVMGroup    = "no_kvm_group"
)

// sandboxNotInGroup is the answer for an account outside group, the group
// that may read and write the device the driver needs (what = "Docker" or
// "/dev/kvm"): the reason names the group, so the person knows what to ask
// IT for (GAP-0257).
func sandboxNotInGroup(group, what, code string) sandboxAvailability {
	why := "your account isn't in the group that can use " + what
	if group = strings.TrimSpace(group); group != "" {
		why = "your account isn't in the " + group + " group that can use " + what
	}
	return sandboxAvailability{Why: why, Code: code}
}

// sandboxUnavailable is the answer "no sandbox can run", for why.
func sandboxUnavailable(why string) sandboxAvailability {
	code, ok := sandboxUnavailableCodes[why]
	if !ok {
		code = "prerequisite_missing"
	}
	return sandboxAvailability{Why: why, Code: code}
}

// sandboxDeviceState is what the POSIX mode of a device the compute
// driver needs grants one account.
type sandboxDeviceState uint8

const (
	// sandboxDeviceMissing: the path does not exist.
	sandboxDeviceMissing sandboxDeviceState = iota
	// sandboxDeviceUsable: the account may read and write it.
	sandboxDeviceUsable
	// sandboxDeviceNotMember: the device's group may read and write it,
	// and the account is not in that group.
	sandboxDeviceNotMember
	// sandboxDeviceDenied: the mode grants the account's class (owner,
	// group member or other) no read-write access, or the path can't be
	// examined.
	sandboxDeviceDenied
	// sandboxDeviceGroupsUnknown: the answer depends on the account's
	// groups, which could not be looked up (the directory is unreachable).
	// The probe then answers provisionally that a sandbox may run.
	sandboxDeviceGroupsUnknown
)

// sandboxDeviceAccess is the probe's look at one device for one account:
// the state and the name of the device's group (for sandboxNotInGroup).
type sandboxDeviceAccess struct {
	State sandboxDeviceState
	Group string
}

// sandboxVMRequired is the answer "the organization requires the MicroVM
// driver (driver_fallback: none) and it can't run for this account", with
// the probe's reason in the caller's words and its registered code.
func sandboxVMRequired(reason string) sandboxAvailability {
	why := (&openshell.DriverUnavailableError{Reason: reason}).Error()
	code := "prerequisite_missing"
	switch reason {
	case openshell.DriverReasonKVMMissing, openshell.DriverReasonCPUVirtualization:
		code = "no_kvm"
	case openshell.DriverReasonKVMAccess:
		code = "no_kvm_access"
	}
	return sandboxAvailability{Why: why, Code: code}
}

// Device paths the compute drivers need.
const (
	sandboxDockerSocketPath = "/var/run/docker.sock"
	sandboxKVMDevicePath    = "/dev/kvm"
	sandboxCPUInfoPath      = "/proc/cpuinfo"
)

// sandboxAvailabilityTTL bounds how long one account's answer is reused:
// the gate runs on every prompt and tool call, and a group change shows up
// within it.
const sandboxAvailabilityTTL = 30 * time.Second

// sandboxAvailabilityMaxEntries bounds the cache; it is cleared when full.
const sandboxAvailabilityMaxEntries = 4096

type sandboxAvailabilityKey struct {
	uid      int
	driver   string
	fallback string
}

type sandboxAvailabilityEntry struct {
	at     time.Time
	answer sandboxAvailability
}

// sandboxAvailabilityProbe judges sandbox availability per account. Tests
// replace its platform and file access.
type sandboxAvailabilityProbe struct {
	goos, goarch string
	// access judges whether uid may read and write path by its owner,
	// group and mode and the uid's groups (sandboxPathAccess).
	access func(path string, uid int) sandboxDeviceAccess
	// cpuInfoPath is read for the CPU's virtualization flags (Linux
	// MicroVM driver); an unreadable file skips that check.
	cpuInfoPath string
	// prerequisite is the lifecycle's OpenShell prerequisite state for the
	// account and driver: "" when met, else why not (caller-facing).
	prerequisite func(cfg *config.Config, uid int, driver string) string
	now          func() time.Time

	mu    sync.Mutex
	cache map[sandboxAvailabilityKey]sandboxAvailabilityEntry
}

func newSandboxAvailabilityProbe() *sandboxAvailabilityProbe {
	return &sandboxAvailabilityProbe{
		goos:         runtime.GOOS,
		goarch:       runtime.GOARCH,
		access:       sandboxPathAccess,
		cpuInfoPath:  sandboxCPUInfoPath,
		prerequisite: sandboxOpenShellPrerequisite,
		now:          time.Now,
	}
}

// defaultSandboxAvailability is the gateway's probe.
var defaultSandboxAvailability = newSandboxAvailabilityProbe()

// sandboxPrerequisitesFile is the record of the OpenShell prerequisites
// the lifecycle last found (enterpriseunix publishPrerequisites), in
// <ConfigDir>/openshell: root's, world-readable and non-secret, written for
// the gateway at every ensure, repair and upgrade.
const sandboxPrerequisitesFile = "prerequisites.json"

// sandboxPrerequisitesMaxBytes bounds the record the gateway reads.
const sandboxPrerequisitesMaxBytes = 64 << 10

// sandboxPrerequisitesPath is where the lifecycle records the
// prerequisites on goos, "" where it records none; tests replace it.
var sandboxPrerequisitesPath = func(goos string) string {
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil || layout.ConfigDir == "" {
		return ""
	}
	return filepath.Join(layout.ConfigDir, "openshell", sandboxPrerequisitesFile)
}

// sandboxPrerequisiteItems is a readiness and its missing items.
type sandboxPrerequisiteItems struct {
	Ready   bool `json:"ready"`
	Missing []struct {
		Item   string `json:"item"`
		Detail string `json:"detail"`
		// Version is the refused release of an installed OpenShell part.
		Version string `json:"version"`
	} `json:"missing"`
}

// sandboxPrerequisitesRecord is the part of the lifecycle's record the
// gateway reads (openshell.PrerequisitesRecord). Ready and Missing are the
// configured driver's; Fallback the docker fallback's, when the lifecycle
// checked one.
type sandboxPrerequisitesRecord struct {
	Version int    `json:"version"`
	Install string `json:"install"`
	Driver  string `json:"driver"`
	sandboxPrerequisiteItems
	Fallback *struct {
		Driver string `json:"driver"`
		sandboxPrerequisiteItems
	} `json:"fallback"`
}

// sandboxOpenShellPrerequisite is the lifecycle's OpenShell prerequisite
// state, from the record it publishes for the gateway. The prerequisites are
// the host's (install mode, driver, version, binaries, devices); the
// account's own access to the driver's devices is judged by the probe.
var sandboxOpenShellPrerequisite = func(cfg *config.Config, _ int, driver string) string {
	record, ok := readSandboxPrerequisites(sandboxPrerequisitesPath(runtime.GOOS))
	why := sandboxPrerequisiteWhy(cfg, runtime.GOOS, driver, record, ok)
	return sandboxSetupSwitches.bound(why, sandboxSetupSwitchKey(cfg, runtime.GOOS, record), time.Now())
}

// sandboxSetupSwitchGrace is how long a switch of the sandbox setup (the
// record names another driver or install mode than the configuration) reads
// as under way. A switch whose ensure failed never rewrites the record, and
// "still setting that up, try again in a few minutes" then stood for good,
// with no contact (GAP-0434); past the grace it reads as not set up, which
// names the organization's contact.
const sandboxSetupSwitchGrace = 30 * time.Minute

// sandboxSetupSwitchClock times the switch under way: since when this
// gateway has seen the record differ from the configuration in one way
// (key). Any other answer ends it.
type sandboxSetupSwitchClock struct {
	mu    sync.Mutex
	key   string
	since time.Time
}

// sandboxSetupSwitches is the gateway's clock of the switch under way.
var sandboxSetupSwitches = &sandboxSetupSwitchClock{}

// bound is why, unless it is the switch under way for longer than
// sandboxSetupSwitchGrace: then the setup is not set up.
func (c *sandboxSetupSwitchClock) bound(why, key string, now time.Time) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if why != sandboxUnavailableSetupChanging {
		c.key, c.since = "", time.Time{}
		return why
	}
	if c.key != key || c.since.IsZero() {
		c.key, c.since = key, now
		return why
	}
	if now.Sub(c.since) >= sandboxSetupSwitchGrace {
		return sandboxUnavailableNotSetUp
	}
	return why
}

// sandboxSetupSwitchKey names a switch: the setup the record names and the
// one configured.
func sandboxSetupSwitchKey(cfg *config.Config, goos string, record sandboxPrerequisitesRecord) string {
	install, want := sandboxConfiguredSetup(cfg, goos)
	return strings.ToLower(strings.TrimSpace(record.Install)) + "/" + strings.ToLower(strings.TrimSpace(record.Driver)) + "->" + install + "/" + want
}

// sandboxConfiguredSetup is the configured OpenShell install mode and
// driver on goos.
func sandboxConfiguredSetup(cfg *config.Config, goos string) (install, driver string) {
	if cfg == nil {
		return "", ""
	}
	install = strings.ToLower(strings.TrimSpace(cfg.Enterprise.OpenShell.Install))
	if install == "" {
		install = config.EnterpriseOpenShellInstallPrerequisite
	}
	return install, cfg.Enterprise.OpenShell.SandboxDriver(goos)
}

// readSandboxPrerequisites reads the lifecycle's record at path. ok is
// false when there is none the gateway can trust: missing, not a regular
// file, not root's or writable by others (sandboxRecordTrusted), too
// large, unreadable or of another version.
func readSandboxPrerequisites(path string) (record sandboxPrerequisitesRecord, ok bool) {
	if path == "" {
		return record, false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !sandboxRecordTrusted(info) {
		return record, false
	}
	f, err := os.Open(path)
	if err != nil {
		return record, false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return record, false
	}
	data, err := io.ReadAll(io.LimitReader(f, sandboxPrerequisitesMaxBytes+1))
	if err != nil || len(data) > sandboxPrerequisitesMaxBytes || json.Unmarshal(data, &record) != nil || record.Version != 1 {
		return sandboxPrerequisitesRecord{}, false
	}
	return record, true
}

// sandboxPrerequisiteWhy says why the lifecycle's record keeps a sandbox on
// driver from running, "" when it doesn't. No record, or one written for
// another install mode or driver than the configuration's, reads as not set
// up: the lifecycle has not prepared OpenShell for the organization's
// settings. The docker fallback of a MicroVM configuration reads the
// record's fallback part, and is not set up without one. A missing item
// reads by what it is, in the caller's words; the details are only in the
// admin views (enterprise status).
func sandboxPrerequisiteWhy(cfg *config.Config, goos, driver string, record sandboxPrerequisitesRecord, ok bool) string {
	if !ok || cfg == nil {
		return sandboxUnavailableNotSetUp
	}
	install, want := sandboxConfiguredSetup(cfg, goos)
	if !strings.EqualFold(strings.TrimSpace(record.Install), install) ||
		!strings.EqualFold(strings.TrimSpace(record.Driver), want) {
		// The lifecycle prepared another setup than the one configured now:
		// the organization switched it, and the switch is under way. Not a
		// missing setup to ask IT about (#1203), for as long as a switch
		// takes (sandboxSetupSwitchGrace, GAP-0434).
		return sandboxUnavailableSetupChanging
	}
	items := record.sandboxPrerequisiteItems
	if driver == config.EnterpriseOpenShellDriverDocker && want != config.EnterpriseOpenShellDriverDocker {
		if record.Fallback == nil || !strings.EqualFold(strings.TrimSpace(record.Fallback.Driver), config.EnterpriseOpenShellDriverDocker) {
			return sandboxUnavailableNotSetUp
		}
		items = record.Fallback.sandboxPrerequisiteItems
	}
	if items.Ready {
		return ""
	}
	why := sandboxUnavailablePrerequisiteOther
	for _, missing := range items.Missing {
		switch strings.ToLower(strings.TrimSpace(missing.Item)) {
		case "openshell cli", "openshell gateway", "microvm driver":
			// The trusted lifecycle record distinguishes a missing binary from
			// one it found but refused for its release. Keep that distinction
			// in the user's doctor/run refusal without changing availability.
			if detail := installedOpenShellPrerequisite(missing.Detail); detail != "" {
				return detail
			}
			if why := sandboxOpenShellRefused(missing.Version); why != "" {
				return why
			}
			return sandboxUnavailableNoOpenShell
		case "openshell pin", "openshell platform":
			if detail := installedOpenShellPrerequisite(missing.Detail); detail != "" {
				return detail
			}
			return sandboxUnavailableNoOpenShell
		case "docker":
			why = sandboxUnavailableDockerMissing
		}
	}
	return why
}

func installedOpenShellPrerequisite(detail string) string {
	detail = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(detail), "openshell: "))
	switch {
	case strings.HasPrefix(detail, "OpenShell ") &&
		(strings.Contains(detail, " runs no DefenseClaw sandbox") || strings.Contains(detail, " is not supported")):
		return detail + "; ask your administrator to upgrade OpenShell"
	case strings.Contains(detail, " is installed, enterprise.openshell.version pins "):
		return "OpenShell " + detail + "; ask your administrator to install the pinned release"
	}
	return ""
}

// sandboxOpenShellRefused is the reason for an OpenShell part the
// administrator installed in a release the host runs no sandbox on (the
// record's version): an installed release is never "not installed"
// (GAP-0266). One outside the supported window is unsupported; a
// supported one the pin does not allow is not the organization's release.
// "" when version cannot be read.
func sandboxOpenShellRefused(version string) string {
	v, err := openshell.ParseVersion(version)
	if err != nil {
		return ""
	}
	if openshell.CheckSupported(v) != nil {
		return "OpenShell " + v.String() + " is installed, but that release is unsupported: sandboxes need OpenShell " +
			openshell.SupportedMin + " or later, below " + openshell.SupportedBelow
	}
	return "OpenShell " + v.String() + " is installed, but it is not the release your organization requires"
}

// sandboxDriverFor is the compute driver managed sandboxes want on goos:
// enterprise.openshell.driver (docker, vm or auto), else vm on macOS and
// docker on Linux.
func sandboxDriverFor(cfg *config.Config, goos string) string {
	if cfg == nil {
		return config.EnterpriseOpenShellConfig{}.SandboxDriver(goos)
	}
	return cfg.Enterprise.OpenShell.SandboxDriver(goos)
}

// sandboxDriverFallbackFor is the docker fallback of an account with floor
// F on goos: docker, none, or "" where none applies.
func sandboxDriverFallbackFor(cfg *config.Config, goos string, floor config.OpenShellAdminConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.Enterprise.OpenShell.SandboxDriverFallback(goos, floor)
}

// check reports whether a sandbox can run for uid (known is false when the
// caller has no kernel-verified uid) under floor F, and on which driver.
func (p *sandboxAvailabilityProbe) check(cfg *config.Config, uid int, known bool, floor config.OpenShellAdminConfig) sandboxAvailability {
	if p.goos == "windows" {
		return sandboxUnavailable(sandboxUnavailableWindows)
	}
	if err := openshell.CheckHost(p.goos, p.goarch); err != nil {
		if p.goos == "darwin" {
			return sandboxUnavailable(sandboxUnavailableAppleSilicon)
		}
		return sandboxUnavailable(sandboxUnavailablePlatform)
	}
	if cfg == nil || !cfg.OpenShell.Enabled {
		return sandboxUnavailable(sandboxUnavailableOff)
	}
	if !known {
		return sandboxUnavailable(sandboxUnavailableAccount)
	}
	if uid == 0 {
		return sandboxUnavailable(sandboxUnavailableRoot)
	}
	key := sandboxAvailabilityKey{uid: uid, driver: sandboxDriverFor(cfg, p.goos), fallback: sandboxDriverFallbackFor(cfg, p.goos, floor)}
	now := p.now()
	p.mu.Lock()
	if entry, ok := p.cache[key]; ok && now.Sub(entry.at) < sandboxAvailabilityTTL {
		p.mu.Unlock()
		return entry.answer
	}
	p.mu.Unlock()
	answer := p.judge(cfg, uid, key.driver, key.fallback)
	if answer.Provisional {
		// A group lookup that failed is retried on the next hook, not held
		// for the TTL.
		return answer
	}
	p.mu.Lock()
	if p.cache == nil || len(p.cache) >= sandboxAvailabilityMaxEntries {
		p.cache = make(map[sandboxAvailabilityKey]sandboxAvailabilityEntry)
	}
	p.cache[key] = sandboxAvailabilityEntry{at: now, answer: answer}
	p.mu.Unlock()
	return answer
}

// judge checks the account's access to what driver needs, then the
// lifecycle's prerequisite state. A Linux MicroVM driver that can't run
// for the account falls back to docker under fallback docker, judged like
// the docker driver.
func (p *sandboxAvailabilityProbe) judge(cfg *config.Config, uid int, driver, fallback string) sandboxAvailability {
	switch driver {
	case config.EnterpriseOpenShellDriverDocker:
		return p.judgeDocker(cfg, uid, openshell.DriverReasonConfigured)
	case config.EnterpriseOpenShellDriverVM, config.EnterpriseOpenShellDriverAuto:
	default:
		return sandboxUnavailable(sandboxUnavailableUnknownDriver)
	}
	if p.goos != "linux" {
		// A Mac's MicroVM driver needs no device the account must be
		// granted (CheckHost already refused Intel Macs), and has no
		// fallback.
		if why := p.prerequisiteWhy(cfg, uid, config.EnterpriseOpenShellDriverVM); why != "" {
			return sandboxUnavailable(why)
		}
		return sandboxAvailability{Available: true, Driver: config.EnterpriseOpenShellDriverVM, DriverReason: openshell.DriverReasonConfigured}
	}
	// Linux needs /dev/kvm read-write for the account (by its modes and
	// groups; the gateway can't open it as the account) and a CPU with
	// virtualization, then the lifecycle's MicroVM prerequisites. KVM whose
	// answer depends on groups that could not be looked up counts as usable,
	// provisionally: the daemon's own probe as the account at sandbox start
	// decides the driver, and falls back or refuses there (GAP-0507).
	vmPrereq := ""
	var kvm sandboxDeviceAccess
	choice, err := openshell.SelectDriver(p.goos, driver, fallback, func() openshell.VMProbeResult {
		result := openshell.VMProbe{
			DevicePath: sandboxKVMDevicePath, CPUInfoPath: p.cpuInfoPath, GOARCH: p.goarch,
			Access: func(path string) (bool, bool) {
				kvm = p.access(path, uid)
				usable := kvm.State == sandboxDeviceUsable || kvm.State == sandboxDeviceGroupsUnknown
				return kvm.State != sandboxDeviceMissing, usable
			},
		}.Run()
		if !result.OK {
			return result
		}
		if vmPrereq = p.prerequisiteWhy(cfg, uid, config.EnterpriseOpenShellDriverVM); vmPrereq != "" {
			return openshell.VMProbeResult{Reason: openshell.DriverReasonVMPrerequisite}
		}
		return result
	})
	var refused *openshell.DriverUnavailableError
	switch {
	case errors.As(err, &refused):
		if refused.Reason == openshell.DriverReasonVMPrerequisite && vmPrereq != "" {
			// The host itself is not set up for MicroVMs: say what, as for
			// any driver.
			return sandboxUnavailable(vmPrereq)
		}
		if kvm.State == sandboxDeviceNotMember {
			// Name the group to ask IT for (GAP-0257), with why it is
			// needed: the MicroVM driver is required (driver_fallback: none).
			answer := sandboxNotInGroup(kvm.Group, sandboxKVMDevicePath, sandboxCodeNoKVMGroup)
			answer.Why = "your organization requires MicroVM sandboxes, and " + answer.Why
			return answer
		}
		return sandboxVMRequired(refused.Reason)
	case err != nil:
		return sandboxUnavailable(sandboxUnavailableUnknownDriver)
	case choice.Driver == openshell.DriverVM:
		docker := p.vmImageDocker(uid)
		if !docker.Available {
			return docker
		}
		return sandboxAvailability{Available: true, Driver: string(choice.Driver), DriverReason: choice.Reason,
			Provisional: kvm.State == sandboxDeviceGroupsUnknown || docker.Provisional}
	}
	// The docker fallback: the same docker access and prerequisites as the
	// docker driver. A MicroVM host prerequisite that is missing while the
	// fallback's are met is the fallback's reason.
	answer := p.judgeDocker(cfg, uid, choice.Reason)
	if !answer.Available && vmPrereq != "" && answer.Code == "prerequisite_missing" {
		return sandboxUnavailable(vmPrereq)
	}
	if !answer.Available && vmPrereq == "" && sandboxDockerAccessCode(answer.Code) {
		// Neither driver can run for the account: name why KVM doesn't
		// first, then why the fallback doesn't, so IT fixes the right one
		// (KVM, which needs no docker group, or Docker; GAP-0462).
		kvmWhy := openshell.DriverReasonText(choice.Reason)
		if kvm.State == sandboxDeviceNotMember {
			kvmWhy = sandboxNotInGroup(kvm.Group, sandboxKVMDevicePath, "").Why
		}
		if kvmWhy != "" {
			answer.Why = kvmWhy + "; and the Docker fallback can't run either: " + answer.Why
		}
	}
	return answer
}

// vmImageDocker checks that uid can use Docker, which the Linux MicroVM
// driver needs too: DefenseClaw builds each harness image for the account in
// Docker, and the driver boots it from there (the root equivalence is
// accepted and documented, O8). An account with KVM and no Docker was told
// sandboxes were ready, then its first run failed on the image build
// (GAP-0511). A socket whose answer depends on groups that could not be
// looked up is usable, provisionally, as in judgeDocker (GAP-0507).
func (p *sandboxAvailabilityProbe) vmImageDocker(uid int) sandboxAvailability {
	access := p.access(sandboxDockerSocketPath, uid)
	var answer sandboxAvailability
	switch access.State {
	case sandboxDeviceUsable:
		return sandboxAvailability{Available: true}
	case sandboxDeviceGroupsUnknown:
		return sandboxAvailability{Available: true, Provisional: true}
	case sandboxDeviceMissing:
		answer = sandboxUnavailable(sandboxUnavailableNoDocker)
	case sandboxDeviceNotMember:
		answer = sandboxNotInGroup(access.Group, "Docker", sandboxCodeNoDockerGroup)
	default:
		answer = sandboxUnavailable(sandboxUnavailableDockerAccess)
	}
	answer.Why = "MicroVM sandboxes start from an agent image built in Docker for your account, and " + lowerFirst(answer.Why)
	return answer
}

// lowerFirst is s with its first letter in lower case, for a reason quoted
// after "and" ("Docker is not running" stays a name).
func lowerFirst(s string) string {
	if strings.HasPrefix(s, "Docker") || s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// sandboxDockerAccessCode reports whether code is a reason the docker
// driver can't run for the account (no Docker, or no access to it).
func sandboxDockerAccessCode(code string) bool {
	switch code {
	case sandboxCodeNoDockerGroup, sandboxUnavailableCodes[sandboxUnavailableNoDocker], sandboxUnavailableCodes[sandboxUnavailableDockerAccess]:
		return true
	}
	return false
}

// judgeDocker checks the docker driver (or the docker fallback, reason
// being the fallback's) for uid: the docker socket by the account's groups,
// then the lifecycle's docker prerequisites. A socket whose answer depends
// on groups that could not be looked up is usable, provisionally: the run
// starts under the default profile, as the profile match does during a
// directory outage, and the daemon finds out at sandbox start whether the
// account can use Docker (GAP-0507).
func (p *sandboxAvailabilityProbe) judgeDocker(cfg *config.Config, uid int, reason string) sandboxAvailability {
	access := p.access(sandboxDockerSocketPath, uid)
	switch access.State {
	case sandboxDeviceMissing:
		return sandboxUnavailable(sandboxUnavailableNoDocker)
	case sandboxDeviceNotMember:
		return sandboxNotInGroup(access.Group, "Docker", sandboxCodeNoDockerGroup)
	case sandboxDeviceDenied:
		return sandboxUnavailable(sandboxUnavailableDockerAccess)
	}
	if why := p.prerequisiteWhy(cfg, uid, config.EnterpriseOpenShellDriverDocker); why != "" {
		return sandboxUnavailable(why)
	}
	return sandboxAvailability{Available: true, Driver: config.EnterpriseOpenShellDriverDocker, DriverReason: reason,
		Provisional: access.State == sandboxDeviceGroupsUnknown}
}

func (p *sandboxAvailabilityProbe) prerequisiteWhy(cfg *config.Config, uid int, driver string) string {
	if p.prerequisite == nil {
		return ""
	}
	return p.prerequisite(cfg, uid, driver)
}
