// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const windowsCoworkRecordName = "cowork-host.json"

// This record is separate from deployment.json, which older releases read
// strictly. The PowerShell transaction snapshots and restores it atomically
// with the files and the two fixed Claude Desktop registry values.
type windowsCoworkOwnership struct {
	SchemaVersion int                         `json:"schema_version"`
	Files         map[string]string           `json:"files"`
	CacheFiles    map[string]string           `json:"cache_files"`
	Values        []enterprisepolicy.RegValue `json:"values"`
	// Directories are the Cowork folder and its Claude parent when the
	// lifecycle created them (Get-DefenseClawCoworkOwnership).
	Directories []string `json:"directories"`
}

type windowsCoworkPlan struct {
	Enabled         bool   `json:"enabled"`
	CacheDirectory  string `json:"cache_directory"`
	PackagePath     string `json:"package_path"`
	ArgumentsPath   string `json:"arguments_path"`
	SourceArchive   string `json:"source_archive"`
	SourceSignature string `json:"source_signature"`
	PackageSHA256   string `json:"package_sha256"`
	SignatureSHA256 string `json:"signature_sha256"`
	Arguments       string `json:"arguments"`
	Vendor          string `json:"vendor"`
	RegistryRefusal string `json:"registry_refusal"`
}

func windowsCoworkPaths() (dir, record string, err error) {
	roots, err := winpath.ResolveTrustedMachineRoots()
	if err != nil {
		return "", "", err
	}
	windowsDir, err := windows.GetWindowsDirectory()
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(filepath.VolumeName(roots.ProgramFiles), filepath.VolumeName(windowsDir)) {
		return "", "", errors.New("the Cowork delivery requires Program Files on the Windows OS drive")
	}
	layout, err := managed.StandaloneWindowsLayoutForRoots(roots.ProgramFiles, roots.ProgramData)
	if err != nil {
		return "", "", err
	}
	return filepath.Join(roots.ProgramFiles, "Claude", "edr-integration"), filepath.Join(layout.LifecycleDir, windowsCoworkRecordName), nil
}

func windowsCoworkArchitecture() (string, error) {
	native, err := windowsEnterpriseNativeMachine()
	if err != nil {
		return "", err
	}
	// The standalone lifecycle runs only on native Windows x64
	// (validateWindowsEnterpriseStandaloneHost), so x64 is the only package.
	if native != windowsImageFileMachineAMD64 {
		return "", fmt.Errorf("the Cowork VM sensor does not support native Windows machine 0x%04x", native)
	}
	return "amd64", nil
}

// windowsCoworkMachineGUID is this host's Cowork device ID when the config
// sets none: HKLM\SOFTWARE\Microsoft\Cryptography MachineGuid (64-bit
// view), normalized to the install arguments' characters.
func windowsCoworkMachineGUID() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("read MachineGuid for the Cowork device ID (or set enterprise.cowork_vm_sensor.device): %w", err)
	}
	defer key.Close()
	value, kind, err := key.GetStringValue("MachineGuid")
	if err != nil || kind != registry.SZ {
		return "", errors.New("HKLM\\SOFTWARE\\Microsoft\\Cryptography has no REG_SZ MachineGuid for the Cowork device ID; set enterprise.cowork_vm_sensor.device")
	}
	return config.NormalizeCoworkDeviceID(value)
}

func windowsCoworkReadOwnership(path, dir string) (windowsCoworkOwnership, error) {
	out := windowsCoworkOwnership{SchemaVersion: 1, Files: map[string]string{}}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err := managed.ValidateTrustedFilePathStrictAncestors(path, "Cowork ownership record"); err != nil {
		return out, err
	}
	body, err := readWindowsEnterpriseBoundedFile(path, 1<<20)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	if out.SchemaVersion != 1 {
		return out, errors.New("unsupported Cowork ownership record")
	}
	if out.Files == nil {
		out.Files = map[string]string{}
	}
	for path, digest := range out.Files {
		if !windowsCoworkOwnedPath(path, dir) || len(digest) != 64 {
			return out, errors.New("invalid Cowork file ownership entry")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return out, errors.New("invalid Cowork ownership digest")
		}
	}
	if len(out.Values) > 2 {
		return out, errors.New("invalid Cowork registry ownership record")
	}
	for _, value := range out.Values {
		if value.Type != enterprisepolicy.RegSZ || (value.Name != enterprisepolicy.CoworkPackageValue && value.Name != enterprisepolicy.CoworkVendorValue) {
			return out, errors.New("invalid Cowork registry ownership entry")
		}
	}
	for _, owned := range out.Directories {
		if !strings.EqualFold(owned, dir) && !strings.EqualFold(owned, filepath.Dir(dir)) {
			return out, errors.New("invalid Cowork directory ownership entry")
		}
	}
	return out, nil
}

func windowsCoworkOwnedPath(path, dir string) bool {
	if !strings.EqualFold(filepath.Dir(path), dir) {
		return false
	}
	name := filepath.Base(path)
	if name == "install.args" {
		return true
	}
	const archive = "defenseclaw-cowork-amd64.tar.gz"
	return name == archive || name == archive+".sig"
}

func windowsCoworkDigest(path string, limit int64) (string, error) {
	if err := managed.ValidateTrustedFilePathStrictAncestors(path, "Cowork asset"); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return "", errors.New("the Cowork asset must be a nonempty regular file within its size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, limit+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type windowsCoworkPlanOps struct {
	paths        func() (string, string, error)
	architecture func() (string, error)
	ownership    func(string, string) (windowsCoworkOwnership, error)
	settings     func(enterprisepolicy.Options, string, string, []enterprisepolicy.RegValue) (bool, string, error)
	digest       func(string, int64) (string, error)
	stat         func(string) (os.FileInfo, error)
	device       func() (string, error)
}

func buildWindowsCoworkPlan(c *config.Config, delivery bool, inputs ...string) (windowsCoworkPlan, error) {
	return buildWindowsCoworkPlanWith(c, delivery, windowsCoworkPlanOps{
		paths: windowsCoworkPaths, architecture: windowsCoworkArchitecture,
		ownership: windowsCoworkReadOwnership, settings: enterprisepolicy.CheckWindowsCoworkSettings,
		digest: windowsCoworkDigest, stat: os.Lstat, device: windowsCoworkMachineGUID,
	}, inputs...)
}

func buildWindowsCoworkPlanWith(c *config.Config, delivery bool, ops windowsCoworkPlanOps, inputs ...string) (windowsCoworkPlan, error) {
	p := windowsCoworkPlan{}
	if c == nil || !c.StandaloneEnterprise() {
		return p, errors.New("the Cowork delivery applies only to the standalone enterprise profile")
	}
	section := c.Enterprise.CoworkVMSensor
	packageInput, signatureInput := "", ""
	if len(inputs) > 0 {
		packageInput = inputs[0]
	}
	if len(inputs) > 1 {
		signatureInput = inputs[1]
	}
	if section.Mode != "on" {
		if packageInput != "" || signatureInput != "" {
			return p, errors.New("the Cowork artifact inputs require enterprise.cowork_vm_sensor.mode: on")
		}
		return p, nil
	}
	p.Enabled = true
	dir, recordPath, err := ops.paths()
	if err != nil {
		return p, err
	}
	arch, err := ops.architecture()
	if err != nil {
		return p, err
	}
	name := "defenseclaw-cowork-" + arch + ".tar.gz"
	if packageInput != "" && filepath.Base(packageInput) != name {
		return p, fmt.Errorf("the Cowork package input must be named %s for this host", name)
	}
	p.PackagePath, p.ArgumentsPath = filepath.Join(dir, name), filepath.Join(dir, "install.args")
	if !filepath.IsAbs(section.SourceDir) || len(filepath.VolumeName(section.SourceDir)) != 2 || strings.ContainsAny(section.SourceDir, "/%\"") || filepath.Clean(section.SourceDir) != section.SourceDir {
		return p, errors.New("the Cowork source_dir must be a canonical local drive path with backslashes")
	}
	p.SourceArchive, p.SourceSignature = filepath.Join(section.SourceDir, name), filepath.Join(section.SourceDir, name+".sig")
	if packageInput != "" || signatureInput != "" {
		cache := filepath.Join(filepath.Dir(recordPath), "cowork-cache")
		if !strings.EqualFold(section.SourceDir, cache) {
			return p, fmt.Errorf("the Cowork artifact inputs require source_dir: %s", cache)
		}
		p.CacheDirectory = cache
		if packageInput != "" {
			p.SourceArchive = packageInput
		}
		if signatureInput != "" {
			p.SourceSignature = signatureInput
		} else if section.SignatureSHA256 == "" {
			p.SourceSignature = ""
		}
	}
	p.PackageSHA256, p.SignatureSHA256 = section.PackageSHA256, section.SignatureSHA256
	p.Vendor = section.Vendor
	device := ""
	if section.Device == "" { // unset: derive this host's own ID
		if device, err = ops.device(); err != nil {
			return p, err
		}
	}
	p.Arguments, err = section.InstallArguments(device)
	if err != nil {
		return p, err
	}
	owned, err := ops.ownership(recordPath, dir)
	if err != nil {
		return p, err
	}
	// An unsigned explicit archive must not hide an administrator's stale
	// signature in the persistent cache and then make the next repair fail.
	// Only an unchanged cache signature already recorded as ours can retire.
	if delivery && p.CacheDirectory != "" && p.SignatureSHA256 == "" {
		cacheSignature := filepath.Join(p.CacheDirectory, name+".sig")
		if _, statErr := ops.stat(cacheSignature); statErr == nil {
			digest, readErr := ops.digest(cacheSignature, 1<<20)
			if readErr != nil || owned.CacheFiles[cacheSignature] == "" || owned.CacheFiles[cacheSignature] != digest {
				return p, errors.New("unsigned Cowork input conflicts with an unowned or changed cache signature; move it aside or pin its signature")
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return p, statErr
		}
	}
	opts := enterprisepolicy.Options{GOOS: "windows", WSL: c.Enterprise.MachinePolicy.WSL()}
	_, p.RegistryRefusal, err = ops.settings(opts, p.PackagePath, p.Vendor, owned.Values)
	if err != nil {
		return p, err
	}
	if delivery {
		got, err := ops.digest(p.SourceArchive, 512<<20)
		if err != nil {
			return p, err
		}
		if got != p.PackageSHA256 {
			return p, errors.New("the Cowork package does not match enterprise.cowork_vm_sensor.package_sha256")
		}
		if p.SourceSignature == "" {
			if p.SignatureSHA256 != "" {
				return p, errors.New("the Cowork signature is pinned but no signature source was supplied")
			}
		} else if _, err := ops.stat(p.SourceSignature); errors.Is(err, os.ErrNotExist) {
			if p.SignatureSHA256 != "" {
				return p, errors.New("the Cowork signature is pinned but missing from source_dir")
			}
			p.SourceSignature = ""
		} else {
			got, err := ops.digest(p.SourceSignature, 1<<20)
			if err != nil {
				return p, err
			}
			if p.SignatureSHA256 == "" || got != p.SignatureSHA256 {
				return p, errors.New("the Cowork signature does not match enterprise.cowork_vm_sensor.signature_sha256")
			}
		}
	}
	return p, nil
}

func newWindowsEnterpriseCoworkInspectCommand() *cobra.Command {
	var configPath, packagePath, signaturePath string
	var beforeACLRepair bool
	cmd := &cobra.Command{Use: "inspect-cowork", Hidden: true, SilenceUsage: true, RunE: func(cmd *cobra.Command, _ []string) error {
		load := loadWindowsEnterpriseStandaloneConfig
		if beforeACLRepair {
			load = loadWindowsCoworkSourceConfig
		}
		c, err := load(configPath)
		if err != nil {
			return err
		}
		p, err := buildWindowsCoworkPlan(c, true, packagePath, signaturePath)
		if err != nil {
			return err
		}
		return newEnterpriseJSONEncoder(cmd.OutOrStdout()).Encode(p)
	}}
	cmd.Flags().StringVar(&configPath, "config", "", "installed standalone administrator config")
	cmd.Flags().StringVar(&packagePath, "cowork-package", "", "SHA-pinned Cowork archive input")
	cmd.Flags().StringVar(&signaturePath, "cowork-signature", "", "SHA-pinned Cowork detached signature input")
	cmd.Flags().BoolVar(&beforeACLRepair, "before-acl-repair", false, "the lifecycle source plan, read before the transaction repairs the runtime ACL")
	return cmd
}

// loadWindowsCoworkSourceConfig is the load of the Cowork source plan, which
// install, upgrade and ensure read before their transaction re-stamps the
// runtime access list. With GAP-0561 the data_dir walk is strict on
// standalone, so a drifted runtime ACL refused this read and ensure failed
// 1603 before it reached the repair. Only that refusal falls back to the
// checks the config preflight runs at the same point: every service-time rule
// except the data_dir ACL. Delivery loads the installed config strictly again
// after the repair, so drift the transaction cannot repair still fails it.
func loadWindowsCoworkSourceConfig(path string) (*config.Config, error) {
	c, err := loadWindowsEnterpriseStandaloneConfig(path)
	var drift *config.ManagedDataDirTrustError
	if err == nil || !errors.As(err, &drift) {
		return c, err
	}
	layout, layoutErr := windowsManagedLayout.standalone()
	if layoutErr != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		path = layout.ConfigPath
	}
	abs, absErr := filepath.Abs(path)
	if absErr != nil {
		return nil, err
	}
	raw, readErr := readConfigV8Source(abs)
	if readErr != nil {
		return nil, err
	}
	pins := windowsEnterpriseServicePins(layout)
	pins[managed.ConfigPathEnv] = abs
	restore := setTemporaryEnvironment(pins)
	defer restore()
	candidate, candidateErr := config.LoadRuntimeV8InspectionCandidateFromBytes(abs, config.V8ManagedChecksView(raw))
	if candidateErr != nil {
		return nil, err
	}
	if err := config.ValidateManagedStandaloneRuntimeCandidate(candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

func applyWindowsEnterpriseCoworkStatus(result *enterprisestatus.Result, c *config.Config) {
	s, _, problems := inspectWindowsCoworkHost(c)
	if s == nil {
		return
	}
	result.CoworkVMSensor = s
	if len(problems) > 0 {
		windowsCoworkIncomplete(result, strings.Join(problems, "; "))
	}
}

// inspectWindowsCoworkHost is the read-only Cowork VM host check status,
// verify and ensure share. It returns no state outside the standalone
// profile, and the plan only when the host could be inspected.
func inspectWindowsCoworkHost(c *config.Config) (*enterprisestatus.CoworkVMSensorState, windowsCoworkPlan, []string) {
	if c == nil || !c.StandaloneEnterprise() {
		return nil, windowsCoworkPlan{}, nil
	}
	s := &enterprisestatus.CoworkVMSensorState{Enabled: c.Enterprise.CoworkVMSensor.Mode == "on"}
	if !s.Enabled {
		return s, windowsCoworkPlan{}, nil
	}
	inspectionFailed := func(err error) (*enterprisestatus.CoworkVMSensorState, windowsCoworkPlan, []string) {
		s.ReasonCodes = []string{"host_inspection_failed"}
		return s, windowsCoworkPlan{}, []string{err.Error()}
	}
	p, err := buildWindowsCoworkPlan(c, false)
	if err != nil {
		return inspectionFailed(err)
	}
	s.PackagePath = p.PackagePath
	dir, recordPath, err := windowsCoworkPaths()
	if err != nil {
		return inspectionFailed(err)
	}
	owned, err := windowsCoworkReadOwnership(recordPath, dir)
	if err != nil {
		return inspectionFailed(err)
	}
	var problems []string
	for path, want := range map[string]string{p.PackagePath: p.PackageSHA256, p.PackagePath + ".sig": p.SignatureSHA256} {
		got, err := windowsCoworkDigest(path, 512<<20)
		readable, readErr := enterprisepolicy.CoworkPublicFileReady(path)
		if err != nil || readErr != nil || !readable || want == "" || got != want {
			s.ReasonCodes = append(s.ReasonCodes, "package_or_signature_not_ready")
			problems = append(problems, path+" is missing, changed, unpinned or unreadable by ordinary users")
		}
	}
	body, err := readWindowsEnterpriseBoundedFile(p.ArgumentsPath, 256)
	readable, readErr := enterprisepolicy.CoworkPublicFileReady(p.ArgumentsPath)
	if err != nil || readErr != nil || !readable || string(body) != p.Arguments {
		s.ReasonCodes = append(s.ReasonCodes, "arguments_not_ready")
		problems = append(problems, "Cowork install.args must contain the configured ASCII arguments and be readable by ordinary users")
	}
	// A missing folder is delivery drift (repair creates it); an existing
	// folder DefenseClaw does not own, or an ancestor such as Program Files,
	// that others can write is destination_untrusted: delivery refuses it,
	// so only the administrator can fix it.
	for current := dir; ; current = filepath.Dir(current) {
		if filepath.Dir(current) == current {
			break
		}
		if _, err := os.Lstat(current); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := managed.ValidateTrustedDirectoryAncestor(current, "Cowork destination ancestor"); err != nil {
			s.ReasonCodes = append(s.ReasonCodes, "destination_untrusted")
			problems = append(problems, err.Error())
			break
		}
	}
	for _, directory := range []string{dir, filepath.Dir(dir)} {
		drift, err := enterprisepolicy.InspectWindowsPublicDir(directory)
		if err != nil || drift.Drifted() {
			code := "destination_permissions_not_ready"
			if _, statErr := os.Lstat(directory); statErr == nil && !slices.ContainsFunc(owned.Directories, func(o string) bool { return strings.EqualFold(o, directory) }) {
				code = "destination_untrusted"
			}
			s.ReasonCodes = append(s.ReasonCodes, code)
			problems = append(problems, "Cowork destination must be admin-owned, admin-writable and readable by ordinary users: "+directory)
		}
	}
	s.HostReady = len(problems) == 0
	opts := enterprisepolicy.Options{GOOS: "windows", WSL: c.Enterprise.MachinePolicy.WSL()}
	ready, refusal, err := enterprisepolicy.CheckWindowsCoworkSettings(opts, p.PackagePath, p.Vendor, owned.Values)
	s.SettingsReady = ready && refusal == "" && err == nil
	if !s.SettingsReady {
		s.ReasonCodes = append(s.ReasonCodes, "machine_settings_not_ready")
		if refusal == "" {
			refusal = "Cowork HKLM REG_SZ settings are missing or could not be verified"
		}
		problems = append(problems, refusal)
	}
	return s, p, problems
}

// windowsEnterpriseCoworkEnsureDrift is the repair a compliant ensure still
// owes the Cowork VM host delivery: PowerShell verify does not check it, so
// a removed package, a changed install.args or deleted HKLM values would
// otherwise leave ensure noop while verify fails. A var for tests.
var windowsEnterpriseCoworkEnsureDrift = func() (reason, detail string) {
	c, err := loadWindowsEnterpriseStandaloneConfig("")
	if err != nil {
		return "", "" // status and verify report an unreadable config
	}
	s, p, _ := inspectWindowsCoworkHost(c)
	return windowsCoworkDriftReason(s, p)
}

// windowsCoworkDriftReason chooses repair only for drift repair can fix.
// An unpinned signature never becomes host_ready and an administrator-owned
// or merge-mode HKLM value is refused by delivery, so repairing those would
// restart every service on each ensure and change nothing; status and verify
// keep reporting them. A host that could not be inspected fails repair too,
// and so does destination_untrusted (an ancestor such as Program Files, or a
// Cowork folder DefenseClaw did not create, that others can write): the
// strict custody checks of delivery refuse it, so it is the administrator's
// to fix. destination_permissions_not_ready (a missing folder, or the ACL of
// a folder DefenseClaw created) does repair.
func windowsCoworkDriftReason(s *enterprisestatus.CoworkVMSensorState, p windowsCoworkPlan) (string, string) {
	if s == nil || !s.Enabled || (s.HostReady && s.SettingsReady) {
		return "", ""
	}
	if p.PackagePath == "" || p.SignatureSHA256 == "" || p.RegistryRefusal != "" || slices.Contains(s.ReasonCodes, "destination_untrusted") {
		return "", ""
	}
	return "drift:cowork_vm_sensor", "Cowork VM sensor host delivery is not ready (" + strings.Join(s.ReasonCodes, ", ") + ")"
}

func windowsCoworkIncomplete(result *enterprisestatus.Result, message string) {
	result.MarkCoverageIncomplete("cowork_vm_sensor_incomplete")
	result.MarkSecurityIncomplete("cowork_vm_sensor_incomplete")
	result.AddWarning("cowork_vm_sensor_incomplete", message)
	if result.Action == "verify" {
		result.AddError("cowork_vm_sensor_incomplete", message)
	}
}
