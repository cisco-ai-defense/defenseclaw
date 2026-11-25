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

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/jsonc"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// OpenClaw security.installPolicy (connectors.openclaw.install_policy):
// OpenClaw runs a trusted local command before it installs or updates a
// skill or plugin and refuses the install unless the command answers allow.
// Setup registers "defenseclaw-gateway connector openclaw install-policy",
// which asks the gateway for its skill or plugin admission. It is written
// only on OpenClaw 2026.8.35 and later (older releases reject the key), only
// when the operator has no installPolicy of their own, and teardown takes it
// out only while it is still exactly what setup wrote.

// OpenClawInstallPolicySince is the first OpenClaw release whose
// security.installPolicy runs an exec command.
const OpenClawInstallPolicySince = "2026.8.35"

// OpenClawWindowsInheritOnlySince is the first OpenClaw release (fs-safe
// 0.26) whose Windows install-policy check skips inherit-only ACEs.
// OpenClaw 2026.8.35 (fs-safe 0.5) counts them, so below a drive root that
// keeps the default inherit-only Users and CREATOR OWNER entries it refuses
// the command (rel-1-0-10 GAP-1170).
const OpenClawWindowsInheritOnlySince = "2026.11.3"

// openClawSkipsInheritOnlyACEs reports an OpenClaw known to skip
// inherit-only ACEs; an unknown version is held to the older rule.
func openClawSkipsInheritOnlyACEs(rawVersion string) bool {
	version := NormalizeAgentVersion("openclaw", rawVersion)
	return version != "" && CompareAgentVersions(version, OpenClawWindowsInheritOnlySince) >= 0
}

// openClawInstallPolicyTooOldError is a Windows command that passes only on
// an OpenClaw that skips inherit-only ACEs.
type openClawInstallPolicyTooOldError struct {
	version string
	cause   error
}

func (e *openClawInstallPolicyTooOldError) Error() string {
	return fmt.Sprintf("OpenClaw %s is too old for strict install policy on Windows (needs %s or later): it counts inherit-only entries, and %v",
		e.version, OpenClawWindowsInheritOnlySince, e.cause)
}

// openClawInstallPolicyOwnerError is an owner DefenseClaw refuses (OpenClaw
// does not check owners).
type openClawInstallPolicyOwnerError struct{ msg string }

func (e *openClawInstallPolicyOwnerError) Error() string { return e.msg }

func (e *openClawInstallPolicyTooOldError) Unwrap() error { return e.cause }

// OpenClawInstallPolicyArgs are the static arguments setup writes.
var OpenClawInstallPolicyArgs = []string{"connector", "openclaw", "install-policy"}

// Environment the install-policy command reads. OpenClaw starts the command
// with an empty environment plus exec.env and the passEnv names.
const (
	OpenClawInstallPolicyTimeoutEnv   = "DEFENSECLAW_INSTALL_POLICY_TIMEOUT_MS"
	OpenClawInstallPolicyTokenFileEnv = "DEFENSECLAW_INSTALL_POLICY_TOKEN_FILE"
	OpenClawInstallPolicyAPIEnv       = "DEFENSECLAW_INSTALL_POLICY_API"
	OpenClawInstallPolicyOutageEnv    = "DEFENSECLAW_INSTALL_POLICY_OUTAGE"
)

var openClawInstallPolicyPassEnv = []string{"HOME", "USERPROFILE", "SystemRoot", "TMPDIR", "TEMP", "TMP"}

// openClawInstallPolicyExecutable is the defenseclaw-gateway binary setup
// names as the command; tests replace it.
var openClawInstallPolicyExecutable = defaultOpenClawInstallPolicyExecutable

// defaultOpenClawInstallPolicyExecutable is this process binary with links
// resolved (OpenClaw refuses a symlinked command), or the defenseclaw-gateway
// next to it when this process is another DefenseClaw binary.
func defaultOpenClawInstallPolicyExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := winpath.EvalLinks(exe); err == nil {
		exe = real
	}
	name := "defenseclaw-gateway"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if strings.EqualFold(filepath.Base(exe), name) {
		return exe, nil
	}
	sibling := filepath.Join(filepath.Dir(exe), name)
	if info, err := os.Lstat(sibling); err == nil && info.Mode().IsRegular() {
		return sibling, nil
	}
	return "", fmt.Errorf("%s is not %s and there is none next to it", exe, name)
}

// openClawInstallPolicySupported reports an OpenClaw known to run
// security.installPolicy exec commands. An unknown version is not written:
// an older OpenClaw does not start with a key it does not know.
func openClawInstallPolicySupported(rawVersion string) bool {
	version := NormalizeAgentVersion("openclaw", rawVersion)
	return version != "" && CompareAgentVersions(version, OpenClawInstallPolicySince) >= 0
}

// openClawInstallPolicyWanted reports whether setup registers the command.
func openClawInstallPolicyWanted(opts SetupOpts) bool {
	return opts.OpenClawInstallPolicy && openClawInstallPolicySupported(openClawObservedVersion(opts))
}

// openClawInstallPolicyBlock is the security.installPolicy value setup
// writes for command, in parsed-JSON form (float64 numbers, []interface{}).
func openClawInstallPolicyBlock(opts SetupOpts, command string) map[string]interface{} {
	timeout := opts.OpenClawInstallPolicyTimeoutMs
	if timeout <= 0 {
		timeout = 30000
	}
	env := map[string]string{OpenClawInstallPolicyTimeoutEnv: strconv.Itoa(timeout)}
	if openClawSeparateUser(opts) {
		// The OpenClaw account cannot read config.yaml or the data folder.
		host, port := splitOpenClawAddr(opts.APIAddr, 18970)
		env[OpenClawInstallPolicyTokenFileEnv] = strings.TrimSpace(opts.OpenClawPluginTokenFile)
		env[OpenClawInstallPolicyAPIEnv] = net.JoinHostPort(host, strconv.Itoa(port))
		outage := "open"
		if opts.OpenClawInstallPolicyFailsClosed || opts.ManagedEnterprise {
			outage = "closed"
		}
		env[OpenClawInstallPolicyOutageEnv] = outage
	} else if opts.DataDir != "" {
		env["DEFENSECLAW_HOME"] = opts.DataDir
	}
	block := map[string]interface{}{
		"enabled": true,
		"targets": []string{"skill", "plugin"},
		"exec": map[string]interface{}{
			"source":            "exec",
			"command":           command,
			"args":              OpenClawInstallPolicyArgs,
			"timeoutMs":         timeout,
			"noOutputTimeoutMs": timeout,
			"passEnv":           openClawInstallPolicyPassEnv,
			"env":               env,
			"trustedDirs":       []string{filepath.Dir(command)},
		},
	}
	raw, _ := json.Marshal(block)
	out := map[string]interface{}{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// openClawInstallPolicyCommand is the command setup writes for opts, or an
// error naming why OpenClaw would refuse it (and so every install).
func openClawInstallPolicyCommand(opts SetupOpts) (string, error) {
	command, err := openClawInstallPolicyExecutable()
	if err != nil {
		return "", err
	}
	if err := openClawInstallPolicyTrusted(command, strings.TrimSpace(opts.OpenClawPluginAccount), openClawObservedVersion(opts)); err != nil {
		var tooOld *openClawInstallPolicyTooOldError
		if errors.As(err, &tooOld) {
			return "", err
		}
		var owner *openClawInstallPolicyOwnerError
		if errors.As(err, &owner) {
			return "", fmt.Errorf("DefenseClaw does not register %s as the install policy command: %v", command, err)
		}
		return "", fmt.Errorf("OpenClaw would refuse %s as its install policy command (%v)", command, err)
	}
	return command, nil
}

// openClawInstallPolicyTrusted is openClawInstallPolicyPathTrusted; tests
// replace it.
var openClawInstallPolicyTrusted = openClawInstallPolicyPathTrusted

var openClawInstallPolicyNotices sync.Map

// noteOpenClawInstallPolicyOnce prints a setup notice once per process and
// key, since setup runs on every gateway start.
func noteOpenClawInstallPolicyOnce(key, format string, args ...interface{}) {
	if _, seen := openClawInstallPolicyNotices.LoadOrStore(key, true); seen {
		return
	}
	fmt.Fprintf(openClawTeardownNoticeOutput, "[connector] openclaw: "+format+"\n", args...)
}

// openClawInstallPolicyOf returns security.installPolicy of a parsed
// openclaw.json and whether security was there at all.
func openClawInstallPolicyOf(cfg map[string]interface{}) (policy interface{}, present, securityPresent bool) {
	security, securityPresent := cfg["security"].(map[string]interface{})
	if !securityPresent {
		_, securityPresent = cfg["security"]
		return nil, false, securityPresent
	}
	policy, present = security["installPolicy"]
	return policy, present, true
}

// looksLikeDefenseClawInstallPolicy reports an installPolicy that runs a
// defenseclaw-gateway with the install-policy arguments.
func looksLikeDefenseClawInstallPolicy(policy interface{}) bool {
	m, _ := policy.(map[string]interface{})
	exec, _ := m["exec"].(map[string]interface{})
	command, _ := exec["command"].(string)
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(command)), ".exe")
	args, _ := json.Marshal(exec["args"])
	want, _ := json.Marshal(OpenClawInstallPolicyArgs)
	return base == "defenseclaw-gateway" && string(args) == string(want)
}

// openClawInstallPolicyRecord is what setup wrote: the exact block, and
// whether openclaw.json had a security object before, so teardown takes out
// an emptied security object only when setup created it.
type openClawInstallPolicyRecord struct {
	Block          map[string]interface{} `json:"block"`
	SecurityBefore bool                   `json:"security_before"`
}

// openClawInstallPolicyStatePath is where setup and the reload refresh keep
// the last install policy state (registered, off, not registered: why), so
// doctor and status can say why OpenClaw does not ask DefenseClaw.
func openClawInstallPolicyStatePath(dataDir string) string {
	return filepath.Join(dataDir, "openclaw-install-policy-state.json")
}

// OpenClawBinaryPath is the openclaw executable discovery read the version
// from (GAP-1237); a state file written before it was recorded has none.
type openClawInstallPolicyStateRecord struct {
	State              string `json:"state"`
	OpenClawVersion    string `json:"openclaw_version,omitempty"`
	OpenClawBinaryPath string `json:"openclaw_binary_path,omitempty"`
	At                 string `json:"at"`
}

func saveOpenClawInstallPolicyState(dataDir, state, version, binaryPath string) {
	if dataDir == "" || state == "" {
		return
	}
	data, err := json.MarshalIndent(openClawInstallPolicyStateRecord{
		State: state, OpenClawVersion: NormalizeAgentVersion("openclaw", version),
		OpenClawBinaryPath: strings.TrimSpace(binaryPath), At: time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err == nil {
		_ = atomicWriteFile(openClawInstallPolicyStatePath(dataDir), append(data, byte(10)), 0o600)
	}
}

func discardOpenClawInstallPolicyState(dataDir string) {
	if dataDir != "" {
		_ = os.Remove(openClawInstallPolicyStatePath(dataDir))
	}
}

func openClawInstallPolicyRecordPath(dataDir string) string {
	return filepath.Join(dataDir, "openclaw-install-policy.json")
}

// loadOpenClawInstallPolicyRecord returns the record setup wrote and whether
// there is one. Only a missing record is none: a record that is there but
// cannot be read (Windows access denied or delete pending) is an error, so
// a refresh fails and is retried instead of taking the registered block for
// the operator's and dropping the record (GAP-1234). A record that does not
// parse is none.
func loadOpenClawInstallPolicyRecord(dataDir string) (openClawInstallPolicyRecord, bool, error) {
	var rec openClawInstallPolicyRecord
	if dataDir == "" {
		return rec, false, nil
	}
	// Shared like the other connector state files, so a setup's atomic
	// replace of the record does not fail on Windows while it is read.
	data, err := readConnectorStateFile(openClawInstallPolicyRecordPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return rec, false, nil
	}
	if err != nil {
		return rec, false, fmt.Errorf("read the install policy record: %w", err)
	}
	if json.Unmarshal(data, &rec) != nil || rec.Block == nil {
		return openClawInstallPolicyRecord{}, false, nil
	}
	return rec, true, nil
}

func saveOpenClawInstallPolicyRecord(dataDir string, rec openClawInstallPolicyRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(openClawInstallPolicyRecordPath(dataDir), append(data, byte(10)), 0o600)
}

func discardOpenClawInstallPolicyRecord(dataDir string) {
	if dataDir != "" {
		_ = os.Remove(openClawInstallPolicyRecordPath(dataDir))
	}
}

// OpenClawInstallPolicyStateWritten is the OpenClaw version (normalized) and
// executable the last setup or refresh wrote the install policy state under;
// "" for what there is no state of or the state does not name. The gateway
// compares the cache with them (GAP-1198, GAP-1237). A state file that is
// there but cannot be read is an error, not "no state" (GAP-1234).
func OpenClawInstallPolicyStateWritten(dataDir string) (version, binaryPath string, err error) {
	if dataDir == "" {
		return "", "", nil
	}
	data, err := readConnectorStateFile(openClawInstallPolicyStatePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	var rec openClawInstallPolicyStateRecord
	if json.Unmarshal(data, &rec) != nil {
		return "", "", nil
	}
	return NormalizeAgentVersion("openclaw", rec.OpenClawVersion), strings.TrimSpace(rec.OpenClawBinaryPath), nil
}

// OpenClawInstallPolicyNotChanged starts every state of a refresh that
// decided nothing: it returned before it looked at the OpenClaw version (no
// data folder, the separate-user layout, no openclaw.json, setup has not
// registered the plugin) or found the version unknown. The gateway moves
// the version it compares the cache with only for a refresh that decided
// (GAP-1234).
const OpenClawInstallPolicyNotChanged = "not changed: "

// OpenClawInstallPolicyDecided reports a refresh state that judged the
// install policy under the OpenClaw version it was given (registered, off,
// or not registered: why).
func OpenClawInstallPolicyDecided(state string) bool {
	return !strings.HasPrefix(state, OpenClawInstallPolicyNotChanged)
}

// Install policy states applyOpenClawInstallPolicy reports.
const (
	openClawInstallPolicyRegistered = "registered"
	openClawInstallPolicyOff        = "off"
	// OpenClawInstallPolicyVersionUnknown: the DefenseClaw block is
	// registered and install_policy is on, but the OpenClaw version cannot be
	// told (discovery cached "" while the executable was replaced mid-scan,
	// after a probe timeout, or from a shell without openclaw on PATH; or a
	// version that does not parse). An unknown version is no evidence that
	// OpenClaw got older, and removing the block would let installs skip
	// DefenseClaw (fail-open), so it stays as it is and the state file keeps
	// the version it was written under. A known version that is too old
	// still removes it.
	OpenClawInstallPolicyVersionUnknown = OpenClawInstallPolicyNotChanged + "OpenClaw version unknown"
)

// applyOpenClawInstallPolicy writes, refreshes or removes the DefenseClaw
// security.installPolicy in openclaw.json after the plugin registration. The
// caller holds the openclaw.json lock. A block the operator wrote, or
// changed, is left as it is. It returns the state: registered, off, or
// "not registered: <reason>".
func applyOpenClawInstallPolicy(configPath string, opts SetupOpts) (string, error) {
	state, err := applyOpenClawInstallPolicyState(configPath, opts)
	if err == nil && state != OpenClawInstallPolicyVersionUnknown {
		saveOpenClawInstallPolicyState(opts.DataDir, state, openClawObservedVersion(opts), openClawObservedExecutable(opts))
	}
	return state, err
}

func applyOpenClawInstallPolicyState(configPath string, opts SetupOpts) (string, error) {
	if opts.DataDir == "" {
		return "not registered: no DefenseClaw data folder", nil
	}
	rec, hasRec, err := loadOpenClawInstallPolicyRecord(opts.DataDir)
	if err != nil {
		return "", err
	}
	original, err := readConnectorStateFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read %s: %w", configPath, err)
	}
	cfg := map[string]interface{}{}
	if len(original) > 0 {
		if cfg, err = parseOpenClawConfig(configPath, original); err != nil {
			return "", err
		}
	}
	current, present, securityBefore := openClawInstallPolicyOf(cfg)
	ours := hasRec && present && reflect.DeepEqual(current, rec.Block)
	if ours && opts.OpenClawInstallPolicy && NormalizeAgentVersion("openclaw", openClawObservedVersion(opts)) == "" {
		// With no record, setup on an OpenClaw of no known version still
		// does not register the block (below).
		return OpenClawInstallPolicyVersionUnknown, nil
	}
	if !openClawInstallPolicyWanted(opts) {
		state := openClawInstallPolicyOff
		if opts.OpenClawInstallPolicy {
			state = fmt.Sprintf("not registered: OpenClaw %q has no security.installPolicy (needs %s or later)",
				NormalizeAgentVersion("openclaw", openClawObservedVersion(opts)), OpenClawInstallPolicySince)
		}
		if ours {
			return state, removeOpenClawInstallPolicy(configPath, opts.DataDir)
		}
		if hasRec {
			discardOpenClawInstallPolicyRecord(opts.DataDir)
		}
		return state, nil
	}
	if present && !ours {
		if hasRec {
			discardOpenClawInstallPolicyRecord(opts.DataDir)
		}
		noteOpenClawInstallPolicyOnce("operator|"+configPath,
			"%s already has a security.installPolicy; DefenseClaw left it and does not add its install admission (remove it to let setup add DefenseClaw)", configPath)
		return "not registered: openclaw.json already has a security.installPolicy of its own", nil
	}
	command, err := openClawInstallPolicyCommand(opts)
	if err != nil {
		noteOpenClawInstallPolicyOnce("command|"+configPath, "install admission is not registered: %v", err)
		state := "not registered: " + err.Error()
		if ours {
			return state, removeOpenClawInstallPolicy(configPath, opts.DataDir)
		}
		return state, nil
	}
	block := openClawInstallPolicyBlock(opts, command)
	if ours && reflect.DeepEqual(current, block) {
		return openClawInstallPolicyRegistered, nil
	}
	if ours {
		securityBefore = rec.SecurityBefore
	}
	if err := saveOpenClawInstallPolicyRecord(opts.DataDir, openClawInstallPolicyRecord{Block: block, SecurityBefore: securityBefore}); err != nil {
		return "", fmt.Errorf("record the install policy: %w", err)
	}
	security, _ := cfg["security"].(map[string]interface{})
	if security == nil {
		security = map[string]interface{}{}
	}
	security["installPolicy"] = block
	cfg["security"] = security
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal %s: %w", configPath, err)
	}
	if err := atomicWriteFile(configPath, append(out, byte(10)), 0o644); err != nil {
		return "", err
	}
	return openClawInstallPolicyRegistered, nil
}

// RefreshInstallPolicy writes, refreshes or removes the DefenseClaw
// security.installPolicy in openclaw.json for opts and nothing else of
// setup, and returns the state it left (registered, off, or why not). The
// gateway calls it when a config reload changes what
// connectors.openclaw.install_policy resolves to (a rule pack switched to or
// from strict changes auto), so the install admission follows the pack
// without another setup (GAP-1128). An OpenClaw home setup has not written
// yet (no DefenseClaw plugin in openclaw.json and no record), and the
// separate-user layout, where DefenseClaw does not edit openclaw.json, are
// left alone; the next setup writes them.
func (c *OpenClawConnector) RefreshInstallPolicy(opts SetupOpts) (string, error) {
	if opts.DataDir == "" {
		return OpenClawInstallPolicyNotChanged + "no DefenseClaw data folder", nil
	}
	if openClawSeparateUser(opts) {
		return OpenClawInstallPolicyNotChanged + "the separate-user layout (run defenseclaw setup openclaw for the block to merge)", nil
	}
	configPath := c.pathsFor(opts).config
	// Only a missing openclaw.json is "not yet". Another error (Windows
	// access denied or delete pending while OpenClaw rewrites it on its
	// first start) fails the refresh, so it is retried instead of reading as
	// a refresh that ran (GAP-1234).
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		return OpenClawInstallPolicyNotChanged + "no " + configPath + " yet", nil
	} else if err != nil {
		return "", fmt.Errorf("openclaw install policy: %w", err)
	}
	_, hasRec, err := loadOpenClawInstallPolicyRecord(opts.DataDir)
	if err != nil {
		return "", fmt.Errorf("openclaw install policy: %w", err)
	}
	if !hasRec {
		registered, err := openClawConfigRegistersDefenseClawErr(configPath)
		if err != nil {
			return "", fmt.Errorf("openclaw install policy: %w", err)
		}
		if !registered {
			return OpenClawInstallPolicyNotChanged + "setup has not registered the DefenseClaw plugin yet", nil
		}
	}
	// The same steps on openclaw.json and its pre-setup record as Setup.
	var state string
	err = openClawConfigLocked(configPath, func() error {
		keepSnapshot, err := openClawSnapshotUsable(opts.DataDir, c.Name(), configPath)
		if err != nil {
			return fmt.Errorf("openclaw config backup: %w", err)
		}
		if keepSnapshot {
			if err := captureManagedFileBackup(opts.DataDir, c.Name(), "openclaw.json", configPath); err != nil {
				return fmt.Errorf("openclaw config backup: %w", err)
			}
		}
		if state, err = applyOpenClawInstallPolicy(configPath, opts); err != nil {
			return fmt.Errorf("openclaw install policy: %w", err)
		}
		if keepSnapshot {
			if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), "openclaw.json", configPath); err != nil {
				return fmt.Errorf("openclaw config backup hash: %w", err)
			}
		}
		return nil
	})
	return state, err
}

// removeOpenClawInstallPolicy takes the DefenseClaw security.installPolicy
// out of openclaw.json when it is still exactly what setup recorded, and
// drops the record. Only those members are cut from the text, so the rest of
// the JSON5 file keeps its bytes. The caller holds the openclaw.json lock.
func removeOpenClawInstallPolicy(configPath, dataDir string) error {
	rec, ok, err := loadOpenClawInstallPolicyRecord(dataDir)
	if err != nil || !ok {
		return err
	}
	data, err := readConnectorStateFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		discardOpenClawInstallPolicyRecord(dataDir)
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath, err)
	}
	out, err := removeOpenClawInstallPolicyText(configPath, data, rec)
	if err != nil {
		return err
	}
	if out != nil {
		if err := atomicWriteFile(configPath, out, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", configPath, err)
		}
	}
	discardOpenClawInstallPolicyRecord(dataDir)
	return nil
}

// removeOpenClawInstallPolicyText returns data without the recorded block
// (and without a security object setup created and left empty), or nil when
// the file does not hold exactly that block.
func removeOpenClawInstallPolicyText(configPath string, data []byte, rec openClawInstallPolicyRecord) ([]byte, error) {
	want, err := parseOpenClawConfig(configPath, data)
	if err != nil {
		return nil, err
	}
	current, present, _ := openClawInstallPolicyOf(want)
	if !present || !reflect.DeepEqual(current, rec.Block) {
		return nil, nil
	}
	security := want["security"].(map[string]interface{})
	delete(security, "installPolicy")
	dropSecurity := len(security) == 0 && !rec.SecurityBefore
	if dropSecurity {
		delete(want, "security")
	}
	out := data
	for pass := 0; pass < 2; pass++ {
		doc, err := jsonc.Parse(out)
		if err != nil {
			return nil, openClawInstallPolicyEditError(configPath, err)
		}
		sec := childValue(doc, "security")
		if sec == nil || !sec.Object {
			break
		}
		if i, ok := sec.Lookup("installPolicy"); ok {
			out = jsonc.Apply(out, sec.RemoveChild(out, i))
			continue
		}
		if dropSecurity && len(sec.Children) == 0 {
			k, _ := doc.Lookup("security")
			out = jsonc.Apply(out, doc.RemoveChild(out, k))
		}
		break
	}
	got, err := parseOpenClawConfig(configPath, out)
	if err != nil || !reflect.DeepEqual(got, want) {
		return nil, openClawInstallPolicyEditError(configPath, err)
	}
	return out, nil
}

func openClawInstallPolicyEditError(configPath string, cause error) error {
	msg := fmt.Sprintf("%s: could not take the DefenseClaw security.installPolicy out without rewriting the file; remove security.installPolicy by hand", configPath)
	if cause != nil {
		return fmt.Errorf("%s: %w", msg, cause)
	}
	return errors.New(msg)
}

// openClawSeparateUserInstallPolicy is the security.installPolicy block the
// administrator adds in the separate-user layout, where DefenseClaw does not
// write openclaw.json, or nil when install admission is off or OpenClaw
// would refuse the command (the OpenClaw account runs it, so it must be
// owned by root or by that account).
func openClawSeparateUserInstallPolicy(opts SetupOpts) map[string]interface{} {
	if !openClawInstallPolicyWanted(opts) {
		return nil
	}
	command, err := openClawInstallPolicyCommand(opts)
	if err != nil {
		noteOpenClawInstallPolicyOnce("separate|"+opts.OpenClawPluginAccount,
			"install admission is left out of the openclaw.json block: %v; install defenseclaw-gateway in a root-owned folder to use it", err)
		return nil
	}
	return openClawInstallPolicyBlock(opts, command)
}

// openClawSeparateUserInstallPolicyMissing names the install policy entry
// openclaw.json lacks in the separate-user layout. A policy of the
// operator (one that does not run defenseclaw-gateway) is left alone.
func openClawSeparateUserInstallPolicyMissing(cfg map[string]interface{}, opts SetupOpts) []string {
	want := openClawSeparateUserInstallPolicy(opts)
	if want == nil {
		return nil
	}
	current, present, _ := openClawInstallPolicyOf(cfg)
	switch {
	case present && reflect.DeepEqual(current, want):
		return nil
	case present && !looksLikeDefenseClawInstallPolicy(current):
		noteOpenClawInstallPolicyOnce("operator-separate|"+opts.OpenClawPluginAccount,
			"openclaw.json already has a security.installPolicy; DefenseClaw left it and does not ask for its install admission")
		return nil
	}
	return []string{"security.installPolicy (DefenseClaw install admission)"}
}
