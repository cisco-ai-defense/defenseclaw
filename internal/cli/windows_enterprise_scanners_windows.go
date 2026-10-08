// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The standalone payload's scanner runtime (cmd/defenseclaw-scanners) lives
// in its own administrator-owned root, not under InstallRoot or StateRoot:
// the installer module checks those trees file by file, and the runtime is
// thousands of files. This lifecycle step owns it: after a successful
// install, upgrade, repair or ensure it installs the staged executable and
// unpacks the runtime; uninstall removes the root; status and verify report
// it, and verify fails while it is not ready, since every scan then fails
// closed.

var (
	windowsScannerRuntimeDir     = managed.StandaloneWindowsScannerRuntimeDir
	windowsScannerGatewayAccount = `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc
	windowsScannerPrepareTimeout = 15 * time.Minute
	windowsScannerSourceCheck    = managed.ValidateTrustedFilePath
)

// windowsScannerRuntimeSDDL: Administrators own the root; LocalSystem and
// Administrators hold full control and the gateway service reads and runs
// it, all inherited. No other account has access.
func windowsScannerRuntimeSDDL(gateway *windows.SID) string {
	return "O:BAG:SY" + windowsScannerRuntimeDACL(gateway)
}

func windowsScannerRuntimeDACL(gateway *windows.SID) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + gateway.String() + ")"
}

// ensureWindowsScannerRuntimeRoot makes root a folder this lifecycle created.
// "prepare" runs a python.exe from under it as an administrator and the
// gateway service runs the same one, so a folder a standard user made first
// (ProgramData lets users create folders) is not adopted: its owner keeps
// WRITE_DAC over everything in it. A root that is not owned by Administrators
// or LocalSystem is removed and created again, with the protected ACL set at
// creation so no user can add a file before the lockdown.
func ensureWindowsScannerRuntimeRoot(root string, gateway *windows.SID) error {
	info, err := os.Lstat(root)
	if err == nil {
		if !info.IsDir() || winpath.RejectReparseChain(root) != nil {
			return fmt.Errorf("%s is not a real folder", root)
		}
		trusted, ownerErr := windowsPathOwnedByAdministrators(root)
		if ownerErr != nil {
			return fmt.Errorf("read the owner of %s: %w", root, ownerErr)
		}
		if !trusted {
			if err := removeWindowsScannerRuntime(); err != nil {
				return fmt.Errorf("replace %s, which an unprivileged account created: %w", root, err)
			}
			err = os.ErrNotExist
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		descriptor, err := windows.SecurityDescriptorFromString(windowsScannerRuntimeDACL(gateway))
		if err != nil {
			return err
		}
		attributes := &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: descriptor,
		}
		pointer, err := winpath.UTF16Ptr(root)
		if err != nil {
			return err
		}
		if err := windows.CreateDirectory(pointer, attributes); err != nil {
			return fmt.Errorf("create %s: %w", root, err)
		}
	} else if err != nil {
		return err
	}
	if err := applyWindowsSDDL(root, windowsScannerRuntimeSDDL(gateway)); err != nil {
		return fmt.Errorf("protect %s: %w", root, err)
	}
	return nil
}

func windowsPathOwnedByAdministrators(path string) (bool, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return false, err
	}
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return false, err
	}
	return owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid), nil
}

func applyWindowsStandaloneScannerRuntime(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if result == nil {
		return
	}
	switch result.Action {
	case "install", "upgrade", "repair", "ensure":
		if len(result.Errors) != 0 || opts == nil {
			return
		}
		source := ""
		if installer := strings.TrimSpace(opts.resolvedInstaller); installer != "" {
			candidate := filepath.Join(filepath.Dir(installer), managed.StandaloneWindowsScannerRuntimeName)
			if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
				source = candidate
			}
		}
		if source == "" {
			// No staged copy to install from (a repair or ensure run from the installed
			// CLI): a runtime that is installed but not unpacked is prepared again, so a
			// prepare that failed half way is not left for a hand clean-up (GAP-0263),
			// and a missing one is reported with the Setup command that installs it.
			reprepareInstalledWindowsScannerRuntime(result)
			return
		}
		if err := installWindowsScannerRuntime(source, opts); err != nil {
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
		// A request refused before its health checks ran reports only the
		// recorded deployment; a standard account cannot read the runtime
		// folder anyway.
		if result.Installed && !windowsEnterpriseResultHasWarning(result, windowsEnterpriseHealthNotChecked) {
			result.Scanners = windowsScannerRuntimeReader()
			// Every scan fails closed without a ready runtime, so verify
			// fails and an MDM detection remediates (GAP-0294).
			message := ""
			if result.Scanners.State != "ready" {
				message = windowsScannerRuntimeUnavailable(result.Scanners.State)
			} else if err := windowsScannerRuntimeServiceCheck(); err != nil {
				// Prepared, but not as the gateway service runs it: every
				// scan failed while status and verify said ok (GAP-0686).
				message = "the skill, MCP and plugin scanner runtime is prepared but the gateway service cannot run it (" + err.Error() +
					"), so every skill, MCP server and plugin install is blocked (scanner failure, fail-closed); run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair"
			}
			if message != "" {
				if result.Action == "verify" {
					result.AddError("scanner_runtime_unavailable", message)
				} else {
					result.AddWarning("scanner_runtime_unavailable", message)
				}
			}
			if result.Scanners.State != "missing" && result.Scanners.JudgeModel == "" {
				result.AddWarning("scanner_judge_missing",
					"the scanners run without an LLM judge (recommended: the quiet policy with the LLM judge); "+
						"set llm.model in the admin config and store its key with `enterprise secret set`, named by enterprise.inspection.llm.credential")
			}
		}
	}
}

// windowsScannerRuntimeReader is readWindowsScannerRuntime; a seam for tests.
var windowsScannerRuntimeReader = readWindowsScannerRuntime

// windowsScannerRuntimeACLCheck checks that only administrators and
// LocalSystem can change the installed runtime root and executable; a seam
// for tests, whose temporary folders are not.
var windowsScannerRuntimeACLCheck = func(root, target string) error {
	if err := managed.ValidateTrustedRuntimeDir(root, "scanner runtime"); err != nil {
		return err
	}
	return managed.ValidateTrustedFilePath(target, "scanner runtime executable")
}

// windowsInstalledScannerRuntimeCheck is every check made before the
// lifecycle runs the installed executable: its access control, then that it
// is the one the payload trust policy admitted (GAP-0311).
func windowsInstalledScannerRuntimeCheck(root, target string) error {
	if err := windowsScannerRuntimeACLCheck(root, target); err != nil {
		return err
	}
	return managed.CheckScannerRuntimeAdmitted(root, target)
}

// windowsScannerRuntimeServiceCheck checks the runtime the way the gateway
// service runs it: the trust check every scan makes, and that the service
// account can read the runtime folder and the security descriptors of its
// parents. A seam for tests.
var windowsScannerRuntimeServiceCheck = func() error {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return err
	}
	if err := managed.ValidateTrustedFilePath(filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName), "scanner runtime"); err != nil {
		return err
	}
	if err := managed.ValidateServiceCanReadTree(root, "scanner runtime", windowsScannerGatewayAccount); err != nil && !managed.IsServiceAccountUnresolved(err) {
		return err
	}
	return nil
}

// installWindowsScannerRuntime copies source into the protected root unless
// the installed copy already matches, then unpacks and compiles the runtime.
// A new executable is admitted first, like every other payload file.
func installWindowsScannerRuntime(source string, opts *windowsEnterpriseLifecycleOptions) error {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return err
	}
	gateway, err := managed.WindowsServiceAccountSID(windowsScannerGatewayAccount)
	if err != nil || gateway == nil {
		return fmt.Errorf("resolve the gateway service SID: %v", err)
	}
	if err := ensureWindowsScannerRuntimeRoot(root, gateway); err != nil {
		return err
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	want, err := windowsEnterpriseFileSHA256(source)
	if err != nil {
		return err
	}
	// The installed copy is kept only when it has the staged bytes and the
	// record says they were admitted. Otherwise the staged copy is admitted,
	// installed when the bytes differ (a copy changed in place is restored),
	// and recorded: every later run of the installed executable checks it
	// against that record first (GAP-0311).
	got, gotErr := windowsEnterpriseFileSHA256(target)
	admitted, _ := managed.ReadScannerRuntimeAdmission(root)
	if gotErr != nil || got != want || admitted != want {
		if err := admitWindowsScannerRuntimePayload(source, want, opts); err != nil {
			return err
		}
		if gotErr != nil || got != want {
			if err := copyWindowsScannerRuntime(source, target, root, want); err != nil {
				return err
			}
		}
		if err := managed.WriteScannerRuntimeAdmission(root, want); err != nil {
			return fmt.Errorf("record the admitted scanner runtime: %w", err)
		}
	}
	if err := managed.ValidateTrustedFilePath(target, "scanner runtime"); err != nil {
		return err
	}
	if err := managed.CheckScannerRuntimeAdmitted(root, target); err != nil {
		return err
	}
	// prepare is a no-op once the runtime is unpacked; prune drops the
	// runtimes earlier builds left.
	for _, step := range []string{"prepare", "prune"} {
		if err := runWindowsScannerRuntime(target, step); err != nil {
			return err
		}
	}
	return nil
}

// admitWindowsScannerRuntimePayload admits the staged scanner executable as
// the installer module admits every other standalone payload file
// (Get-DefenseClawSourceDescriptor), before this lifecycle copies it into the
// protected root and runs it as an administrator, and the gateway service
// runs it on every scan (GAP-0311). The source must be writable only by
// administrators, and carry a valid Authenticode signature (from a signer
// --allowed-signer pins, when any is given) or, in hash_pinned mode, the
// SHA-256 the payload manifest pins. --allow-unsigned waives only the
// signature, as it does there. digest is the SHA-256 of source.
func admitWindowsScannerRuntimePayload(source, digest string, opts *windowsEnterpriseLifecycleOptions) error {
	if err := windowsScannerSourceCheck(source, "scanner runtime payload"); err != nil {
		return err
	}
	if opts.allowUnsigned {
		return nil
	}
	status := "not valid"
	if _, certificate, err := verifyWindowsAuthenticode(source); err == nil {
		if len(opts.allowedSigners) == 0 {
			return nil
		}
		thumbprint := sha256.Sum256(certificate)
		if slices.Contains(opts.allowedSigners, hex.EncodeToString(thumbprint[:])) {
			return nil
		}
		status = "valid, from a signer --allowed-signer does not pin"
	} else if opts.trustMode == windowsEnterpriseTrustHashPinned {
		if pin, ok := opts.payloadPins[strings.ToLower(filepath.Base(source))]; ok && pin == digest {
			return nil
		}
	}
	return fmt.Errorf("%s is not admitted by the standalone payload trust policy (Authenticode %s; trust mode %s)",
		source, status, opts.trustMode)
}

func windowsEnterpriseResultHasWarning(result *enterprisestatus.Result, code string) bool {
	for _, warning := range result.Warnings {
		if warning.Code == code {
			return true
		}
	}
	return false
}

// windowsScannerRuntimeUnavailable says what a scanner runtime that is not
// ready blocks and what restores it.
func windowsScannerRuntimeUnavailable(state string) string {
	const blocked = "so every skill, MCP server and plugin install is blocked (scanner failure, fail-closed)"
	if state == "untrusted" {
		return "the skill, MCP and plugin scanner runtime executable is not the one the payload trust policy admitted " +
			"(it was changed or replaced outside DefenseClaw), so DefenseClaw does not run it, " + blocked +
			"; run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair to restore the payload copy"
	}
	if state == "not_prepared" {
		return "the skill, MCP and plugin scanner runtime is installed but not prepared, " + blocked +
			"; run enterprise windows repair, or DefenseClawSetup-Enterprise-Standalone-x64.exe /repair, to prepare it"
	}
	return "the skill, MCP and plugin scanner runtime is missing, " + blocked +
		"; run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair (or /ensure) to install it"
}

// reprepareInstalledWindowsScannerRuntime unpacks the runtime of an installed
// scanners executable whose state is not_prepared. A ready runtime is left
// alone. A missing one can only come from a Setup payload, which this run
// does not have, so it is reported.
func reprepareInstalledWindowsScannerRuntime(result *enterprisestatus.Result) {
	current := readWindowsScannerRuntime()
	if current.State == "ready" {
		return
	}
	if current.State == "missing" || current.State == "untrusted" {
		result.AddWarning("scanner_runtime_unavailable", windowsScannerRuntimeUnavailable(current.State))
		result.Scanners = current
		return
	}
	root, err := windowsScannerRuntimeDir()
	if err == nil {
		target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
		if err = windowsInstalledScannerRuntimeCheck(root, target); err == nil {
			for _, step := range []string{"prepare", "prune"} {
				if err = runWindowsScannerRuntime(target, step); err != nil {
					break
				}
			}
		}
	}
	if err != nil {
		result.AddWarning("scanner_runtime_unavailable",
			"the skill, MCP and plugin scanners could not be installed, so installs are blocked until they are: "+err.Error())
	}
	result.Scanners = readWindowsScannerRuntime()
}

// windowsScannerProgress receives a scanner runtime step progress lines
// (stderr: the JSON result stays alone on stdout), and the heartbeat paces
// the still-running lines. Seams for tests.
var (
	windowsScannerProgress  io.Writer = os.Stderr
	windowsScannerHeartbeat           = time.Minute
)

// runWindowsScannerRuntime runs one scanner runtime step with a bounded wait.
// Its own messages and a line every heartbeat go to windowsScannerProgress as
// it runs: a first prepare on a cold disk took 13 minutes with no output, so
// an administrator could not tell it from a hang (GAP-0642).
func runWindowsScannerRuntime(executable, step string) error {
	ctx, cancel := context.WithTimeout(context.Background(), windowsScannerPrepareTimeout)
	defer cancel()
	progress := &windowsScannerLockedWriter{w: windowsScannerProgress}
	if step == "prepare" {
		fmt.Fprintf(progress, "[scanners] preparing the skill, MCP and plugin scanner runtime; a first install takes a few minutes, at most %s\n", windowsScannerPrepareTimeout)
	}
	var stdout bytes.Buffer
	lines := &windowsScannerLineWriter{out: progress}
	command := processutil.CommandContext(ctx, executable, step)
	command.Stdout, command.Stderr = &stdout, lines
	start := time.Now()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(windowsScannerHeartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				fmt.Fprintf(progress, "[scanners] %s is still running: %s elapsed, stopped after %s\n",
					step, time.Since(start).Round(time.Second), windowsScannerPrepareTimeout)
			}
		}
	}()
	err := processutil.RunTree(command)
	close(done)
	lines.flush()
	out := append(stdout.Bytes(), lines.captured.Bytes()...)
	if err == nil && step == "prepare" {
		fmt.Fprintf(progress, "[scanners] the scanner runtime is prepared (%s)\n", time.Since(start).Round(time.Second))
	}
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		// GAP-0297: Windows reports a process the deadline killed as a bare
		// "exit status 1", which hid the cause.
		return fmt.Errorf("%s the scanner runtime: timed out after %s", step, windowsScannerPrepareTimeout)
	}
	if err != nil {
		return fmt.Errorf("%s the scanner runtime: %v: %s", step, err, windowsEnterpriseBoundedDiagnostic(strings.TrimSpace(string(out))))
	}
	return nil
}

// windowsScannerLockedWriter serializes the step output and the heartbeat.
type windowsScannerLockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *windowsScannerLockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// windowsScannerLineWriter passes the step stderr on line by line, prefixed,
// and keeps a bounded copy for the error diagnostic.
type windowsScannerLineWriter struct {
	out      io.Writer
	pending  []byte
	captured bytes.Buffer
}

func (l *windowsScannerLineWriter) Write(p []byte) (int, error) {
	if l.captured.Len() < 64<<10 {
		l.captured.Write(p)
	}
	l.pending = append(l.pending, p...)
	for {
		index := bytes.IndexByte(l.pending, '\n')
		if index < 0 {
			break
		}
		if line := bytes.TrimSpace(l.pending[:index]); len(line) > 0 {
			fmt.Fprintf(l.out, "[scanners] %s\n", line)
		}
		l.pending = l.pending[index+1:]
	}
	return len(p), nil
}

func (l *windowsScannerLineWriter) flush() {
	if line := bytes.TrimSpace(l.pending); len(line) > 0 {
		fmt.Fprintf(l.out, "[scanners] %s\n", line)
	}
	l.pending = nil
}

// copyWindowsScannerRuntime copies source next to target, unpacks its
// runtime from there, and only then swaps it into place, so the gateway's
// scans never run an installed image whose runtime is not unpacked yet.
func copyWindowsScannerRuntime(source, target, root, want string) error {
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
	if want != "" {
		if got, err := windowsEnterpriseFileSHA256(tmp); err != nil || got != want {
			_ = os.Remove(tmp)
			return errors.New("the copied scanner runtime does not match the payload")
		}
		if err := runWindowsScannerRuntime(tmp, "prepare"); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	// A scan the gateway is running keeps the installed image mapped, and
	// Windows refuses to replace a mapped image but lets it be renamed: move
	// it aside first, and remove it once nothing runs it.
	previous := ""
	if _, err := os.Lstat(target); err == nil {
		previous = filepath.Join(root, ".scanners-"+hex.EncodeToString(suffix)+".old")
		if err := os.Rename(target, previous); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("move the installed scanner runtime aside: %w", err)
		}
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		if previous != "" {
			_ = os.Rename(previous, target)
		}
		return fmt.Errorf("install the scanner runtime: %w", err)
	}
	removeStaleWindowsScannerCopies(root)
	return nil
}

// removeStaleWindowsScannerCopies removes earlier runtimes moved aside and
// interrupted copies. One a scan still runs stays until the next install.
func removeStaleWindowsScannerCopies(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type().IsRegular() && strings.HasPrefix(name, ".scanners-") &&
			(strings.HasSuffix(name, ".old") || strings.HasSuffix(name, ".tmp")) {
			_ = os.Remove(filepath.Join(root, name))
		}
	}
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
	// Status and verify run this executable with elevated caller privileges.
	// Check the runtime root as a protected directory, then the executable
	// and its ancestors, before invoking even the read-only versions command.
	if windowsScannerRuntimeACLCheck(root, target) != nil {
		return state
	}
	state.Policy, state.JudgeModel = readWindowsStandaloneScannerSettings()
	// Then that it is the executable the payload trust policy admitted: an
	// administrator-only folder does not stop an administrator, or a process
	// running as one, from replacing it in place (GAP-0311).
	if managed.CheckScannerRuntimeAdmitted(root, target) != nil {
		state.State = "untrusted"
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

// writeWindowsEnterpriseScanners prints the scanners line of a status
// summary: state, the pinned versions, the policy and the judge model.
func writeWindowsEnterpriseScanners(output io.Writer, scanners *enterprisestatus.ScannerRuntime) {
	if scanners == nil {
		return
	}
	versions := make([]string, 0, len(scanners.Versions))
	for _, name := range []string{"skill-scanner", "mcp-scanner", "litellm", "python"} {
		if version := scanners.Versions[name]; version != "" {
			versions = append(versions, name+" "+version)
		}
	}
	judge := scanners.JudgeModel
	if judge == "" {
		judge = "none"
	}
	fmt.Fprintf(output, "  Scanners: %s (%s); policy %s; judge %s\n",
		scanners.State, strings.Join(versions, ", "), scanners.Policy, judge)
}
