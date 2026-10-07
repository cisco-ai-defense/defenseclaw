// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The standalone payload's scanner runtime (cmd/defenseclaw-scanners) lives
// in its own administrator-owned root, not under InstallRoot or StateRoot:
// the installer module checks those trees file by file, and the runtime is
// thousands of files. This lifecycle step owns it: after a successful
// install, upgrade, repair or ensure it installs the staged executable and
// unpacks the runtime; uninstall removes the root; status and verify report
// it. A payload without the runtime (an older Setup) changes nothing.

var (
	windowsScannerRuntimeDir     = managed.StandaloneWindowsScannerRuntimeDir
	windowsScannerGatewayAccount = `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc
	windowsScannerPrepareTimeout = 15 * time.Minute
)

// windowsScannerRuntimeSDDL: Administrators own the root; LocalSystem and
// Administrators hold full control and the gateway service reads and runs
// it, all inherited. No other account has access.
func windowsScannerRuntimeSDDL(gateway *windows.SID) string {
	return "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + gateway.String() + ")"
}

func applyWindowsStandaloneScannerRuntime(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if result == nil {
		return
	}
	switch result.Action {
	case "install", "upgrade", "repair", "ensure":
		if len(result.Errors) != 0 || opts == nil || strings.TrimSpace(opts.resolvedInstaller) == "" {
			return
		}
		source := filepath.Join(filepath.Dir(opts.resolvedInstaller), managed.StandaloneWindowsScannerRuntimeName)
		if info, err := os.Lstat(source); err != nil || !info.Mode().IsRegular() {
			return
		}
		if err := installWindowsScannerRuntime(source); err != nil {
			result.AddWarning("scanner_runtime_unavailable",
				"the skill, MCP and plugin scanners could not be installed, so installs are blocked until they are: "+err.Error())
		}
		result.Scanners = readWindowsScannerRuntime()
	case "uninstall":
		if len(result.Errors) != 0 {
			return
		}
		if err := removeWindowsScannerRuntime(); err != nil {
			result.AddWarning("scanner_runtime_left", "the scanner runtime folder could not be removed: "+err.Error())
		}
	case "status", "verify":
		if result.Installed {
			result.Scanners = readWindowsScannerRuntime()
			if result.Scanners != nil && result.Scanners.State != "missing" && result.Scanners.JudgeModel == "" {
				result.AddWarning("scanner_judge_missing",
					"the scanners run without an LLM judge (recommended: the quiet policy with the LLM judge); "+
						"set llm.model in the admin config and store its key with `enterprise secret set`, named by enterprise.inspection.llm.credential")
			}
		}
	}
}

// installWindowsScannerRuntime copies source into the protected root unless
// the installed copy already matches, then unpacks and compiles the runtime.
func installWindowsScannerRuntime(source string) error {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return err
	}
	gateway, err := managed.WindowsServiceAccountSID(windowsScannerGatewayAccount)
	if err != nil || gateway == nil {
		return fmt.Errorf("resolve the gateway service SID: %v", err)
	}
	if info, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create %s: %w", root, err)
		}
	} else if err != nil {
		return err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real folder", root)
	}
	if err := applyWindowsSDDL(root, windowsScannerRuntimeSDDL(gateway)); err != nil {
		return fmt.Errorf("protect %s: %w", root, err)
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	want, err := windowsEnterpriseFileSHA256(source)
	if err != nil {
		return err
	}
	if got, err := windowsEnterpriseFileSHA256(target); err != nil || got != want {
		if err := copyWindowsScannerRuntime(source, target, root); err != nil {
			return err
		}
		if got, err := windowsEnterpriseFileSHA256(target); err != nil || got != want {
			return errors.New("the installed scanner runtime does not match the payload")
		}
	}
	if err := managed.ValidateTrustedFilePath(target, "scanner runtime"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), windowsScannerPrepareTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, target, "prepare").CombinedOutput()
	if err != nil {
		return fmt.Errorf("prepare the scanner runtime: %v: %s", err, windowsEnterpriseBoundedDiagnostic(strings.TrimSpace(string(out))))
	}
	return nil
}

func copyWindowsScannerRuntime(source, target, root string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(root, ".scanners-"+hex.EncodeToString(suffix)+".tmp")
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install the scanner runtime: %w", err)
	}
	return nil
}

// removeWindowsScannerRuntime removes the scanner runtime root. It refuses
// a root that is a link, so it never follows one out of ProgramData.
func removeWindowsScannerRuntime() error {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real folder", root)
	}
	if !strings.EqualFold(filepath.Base(root), "DefenseClaw-ScannerRuntime") {
		return fmt.Errorf("refusing to remove %s", root)
	}
	return os.RemoveAll(root)
}

// readWindowsScannerRuntime reports the installed runtime, its versions and
// the scanner policy and judge the admin config sets.
func readWindowsScannerRuntime() *enterprisestatus.ScannerRuntime {
	state := &enterprisestatus.ScannerRuntime{State: "missing"}
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return state
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if info, err := os.Lstat(target); err != nil || !info.Mode().IsRegular() {
		return state
	}
	state.State = "not_prepared"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, target, "versions").Output(); err == nil {
		var report struct {
			Versions map[string]string `json:"versions"`
			Prepared bool              `json:"prepared"`
		}
		if json.Unmarshal(out, &report) == nil {
			state.Versions = report.Versions
			if report.Prepared {
				state.State = "ready"
			}
		}
	}
	state.Policy, state.JudgeModel = readWindowsStandaloneScannerSettings()
	return state
}

// readWindowsStandaloneScannerSettings reads the skill scanner policy and
// its judge model from the installed admin config.
func readWindowsStandaloneScannerSettings() (string, string) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", ""
	}
	body, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, 4<<20)
	if err != nil {
		return "", ""
	}
	var document struct {
		LLM struct {
			Model string `yaml:"model"`
		} `yaml:"llm"`
		Scanners struct {
			SkillScanner struct {
				Policy string `yaml:"policy"`
				LLM    struct {
					Model string `yaml:"model"`
				} `yaml:"llm"`
			} `yaml:"skill_scanner"`
		} `yaml:"scanners"`
	}
	if yaml.Unmarshal(trimWindowsJSONBOM(body), &document) != nil {
		return "", ""
	}
	model := strings.TrimSpace(document.Scanners.SkillScanner.LLM.Model)
	if model == "" {
		model = strings.TrimSpace(document.LLM.Model)
	}
	policy := strings.TrimSpace(document.Scanners.SkillScanner.Policy)
	if policy == "" {
		policy = config.DefaultSkillScannerPolicy
	}
	return policy, model
}
