//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/productlayout"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// The strict and permissive rule packs a managed Windows standalone install
// ships (#1445). The lifecycle transaction runs the installed gateway's
// hidden `enterprise windows shipped-rule-packs` right after it swaps the
// binaries and before the config check and the first start: the binary
// writes the packs it embeds (policyassets) to
// <ProgramData>\Cisco\DefenseClaw-RulePacks\<digest16>, a folder of its own,
// so the files are the bytes of the signed payload. Each release resolves
// only its own folder (config.WindowsShippedRulePackDir), so a rollback needs
// nothing restored and an older release's folder stays for it. The gateway
// refuses a shipped folder whose files are not its own; status and verify
// fail, and ensure repairs, while a pack the config selects is missing or
// changed; uninstall removes the root once no deployment is left.

// windowsShippedRulePacksDACL: LocalSystem and Administrators hold full
// control and every service reads, all inherited; standard users have no
// access (a pack is policy, GAP-0386). The read grant names NT
// AUTHORITY\SERVICE, which the gateway's virtual account carries
// (managed.ValidateServiceCanReadTree checks it), because the gateway's own
// service SID does not resolve before the first install creates the service.
const windowsShippedRulePacksDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;SU)"

// windowsShippedRulePacksSDDL is that DACL with Administrators as the owner.
const windowsShippedRulePacksSDDL = "O:BAG:SY" + windowsShippedRulePacksDACL

// windowsShippedRulePacksReportSchema is the schema of the command's report,
// which the installer module checks (Install-DefenseClawStandaloneShippedRulePacks).
const windowsShippedRulePacksReportSchema = 1

var (
	// windowsShippedRulePacksRootDir and windowsShippedRulePacksTreeTrust
	// are seams for tests.
	windowsShippedRulePacksRootDir   = managed.StandaloneWindowsShippedRulePacksDir
	windowsShippedRulePacksTreeTrust = managed.ValidateTrustedRulePackTree
)

type windowsShippedRulePacksReport struct {
	SchemaVersion int      `json:"schema_version"`
	OK            bool     `json:"ok"`
	Folder        string   `json:"folder,omitempty"`
	Changed       bool     `json:"changed"`
	Notes         []string `json:"notes,omitempty"`
	Error         string   `json:"error,omitempty"`
}

func newWindowsShippedRulePacksCommand() *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{
		Use:          "shipped-rule-packs",
		Short:        "Write the strict and permissive rule packs this release ships",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWindowsShippedRulePacks(cmd.OutOrStdout())
		},
	}
	// The report is always JSON; the flag keeps the lifecycle helpers' calling shape.
	command.Flags().BoolVar(&jsonOutput, "json", true, "print the JSON report")
	return command
}

func runWindowsShippedRulePacks(out io.Writer) error {
	report := windowsShippedRulePacksReport{SchemaVersion: windowsShippedRulePacksReportSchema}
	var err error
	if !windowsEnterpriseIsElevated() {
		err = errors.New("writing the shipped rule packs needs LocalSystem or an elevated administrator")
	} else {
		report.Folder, report.Changed, report.Notes, err = installWindowsShippedRulePacks()
	}
	if err != nil {
		report.Error = err.Error()
	} else {
		report.OK = true
	}
	encoded, marshalErr := json.Marshal(report)
	if marshalErr != nil {
		return marshalErr
	}
	fmt.Fprintln(out, string(encoded))
	return err
}

// installWindowsShippedRulePacks writes this binary's shipped packs to its
// folder and returns the folder and whether it changed anything. A folder
// that already holds exactly those files, administrator-only, is left as it
// is, so a repeated ensure changes nothing. Otherwise a fresh copy is written
// beside it, checked, and renamed into place, so no reader ever sees a half
// written pack.
func installWindowsShippedRulePacks() (string, bool, []string, error) {
	root, err := windowsShippedRulePacksRootDir()
	if err != nil {
		return "", false, nil, fmt.Errorf("resolve the shipped rule pack folder from the trusted ProgramData registration: %w", err)
	}
	name, err := policyassets.ShippedRulePackFolderName()
	if err != nil {
		return "", false, nil, err
	}
	files, err := policyassets.ShippedRulePackFiles()
	if err != nil {
		return "", false, nil, err
	}
	folder := filepath.Join(root, name)
	// Every folder and file written below is owned by Administrators, also
	// when the built-in Administrator runs this (GAP-1718).
	restoreOwner, err := adoptWindowsAdministratorsDefaultOwner()
	if err != nil {
		return folder, false, nil, err
	}
	defer restoreOwner()
	serviceAccount := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	var notes []string
	note, err := ensureWindowsShippedRulePacksRoot(root)
	if err != nil {
		return folder, false, nil, err
	}
	if note != "" {
		notes = append(notes, note)
	}
	notes = append(notes, removeWindowsShippedRulePacksScratch(root)...)
	if windowsShippedRulePacksProblem(folder, files, serviceAccount) == "" {
		return folder, false, notes, nil
	}
	suffix, err := windowsShippedRulePacksSuffix()
	if err != nil {
		return folder, false, notes, err
	}
	staging := filepath.Join(root, "."+name+".new-"+suffix)
	if err := writeWindowsShippedRulePacksCopy(staging, files); err != nil {
		_ = os.RemoveAll(staging)
		return folder, false, notes, err
	}
	if problem := windowsShippedRulePacksProblem(staging, files, serviceAccount); problem != "" {
		_ = os.RemoveAll(staging)
		return folder, false, notes, fmt.Errorf("the copy written to %s failed its check: %s", staging, problem)
	}
	if _, err := os.Lstat(folder); err == nil {
		// The folder is not this release's copy (a file was changed or
		// added, or its access list was loosened): move it aside, put the
		// checked copy in its place and remove the old one.
		old := filepath.Join(root, "."+name+".old-"+suffix)
		if err := renameWindowsShippedRulePacks(folder, old); err != nil {
			_ = os.RemoveAll(staging)
			return folder, false, notes, fmt.Errorf("move the changed folder %s aside: %w", folder, err)
		}
		if err := renameWindowsShippedRulePacks(staging, folder); err != nil {
			_ = renameWindowsShippedRulePacks(old, folder)
			_ = os.RemoveAll(staging)
			return folder, false, notes, fmt.Errorf("put the shipped rule packs in %s: %w", folder, err)
		}
		if err := os.RemoveAll(old); err != nil {
			notes = append(notes, fmt.Sprintf("the replaced folder %s stays: %v", old, err))
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := renameWindowsShippedRulePacks(staging, folder); err != nil {
			_ = os.RemoveAll(staging)
			return folder, false, notes, fmt.Errorf("put the shipped rule packs in %s: %w", folder, err)
		}
	} else {
		_ = os.RemoveAll(staging)
		return folder, false, notes, err
	}
	if problem := windowsShippedRulePacksProblem(folder, files, serviceAccount); problem != "" {
		return folder, true, notes, fmt.Errorf("%s failed its check after it was written: %s", folder, problem)
	}
	return folder, true, notes, nil
}

// ensureWindowsShippedRulePacksRoot makes root a folder an administrator
// created, administrator-only. ProgramData lets standard users create
// folders, and the owner of a folder keeps WRITE_DAC over it, so a root
// that Administrators or LocalSystem do not own (or a link) is moved aside,
// never adopted, and created again with its access list set at creation.
func ensureWindowsShippedRulePacksRoot(root string) (string, error) {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
			return "", err
		}
		return "", createWindowsShippedRulePacksDir(root)
	}
	if err != nil {
		return "", err
	}
	trusted := info.IsDir() && info.Mode()&os.ModeSymlink == 0 && winpath.RejectReparseChain(root) == nil
	if trusted {
		owned, ownerErr := windowsPathOwnedByAdministrators(root)
		if ownerErr != nil {
			return "", fmt.Errorf("read the owner of %s: %w", root, ownerErr)
		}
		trusted = owned
	}
	if trusted {
		return "", applyWindowsSDDL(root, windowsShippedRulePacksSDDL)
	}
	suffix, err := windowsShippedRulePacksSuffix()
	if err != nil {
		return "", err
	}
	aside := root + ".untrusted-" + suffix
	if err := os.Rename(root, aside); err != nil {
		return "", fmt.Errorf("%s exists and an account other than Administrators or LocalSystem created it, and it could not be moved aside: %w; remove it and run again", root, err)
	}
	if err := createWindowsShippedRulePacksDir(root); err != nil {
		return "", err
	}
	return fmt.Sprintf("moved %s, which an account other than Administrators or LocalSystem created, to %s; remove that folder", root, aside), nil
}

// createWindowsShippedRulePacksDir creates path with the protected access
// list set at creation, so no account can add a file before the lockdown.
func createWindowsShippedRulePacksDir(path string) error {
	descriptor, err := windows.SecurityDescriptorFromString(windowsShippedRulePacksDACL)
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(pointer, attributes); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := applyWindowsSDDL(path, windowsShippedRulePacksSDDL); err != nil {
		return fmt.Errorf("protect %s: %w", path, err)
	}
	return nil
}

// writeWindowsShippedRulePacksCopy writes files into the new folder dir; the
// folders and files below it inherit its access list.
func writeWindowsShippedRulePacksCopy(dir string, files []policyassets.File) error {
	if err := createWindowsShippedRulePacksDir(dir); err != nil {
		return err
	}
	for _, file := range files {
		path := filepath.Join(dir, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, file.Data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// windowsShippedRulePacksProblem is "" when folder holds exactly files (no
// other file, folder or link) and no standard user can change it; otherwise
// it says what is wrong.
func windowsShippedRulePacksProblem(folder string, files []policyassets.File, serviceAccount string) string {
	info, err := os.Lstat(folder)
	if errors.Is(err, os.ErrNotExist) {
		return "the folder is missing"
	}
	if err != nil {
		return "the folder cannot be read: " + err.Error()
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || winpath.RejectReparseChain(folder) != nil {
		return "it is not a real folder"
	}
	want := make(map[string][]byte, len(files))
	wantDirs := map[string]bool{}
	for _, file := range files {
		rel := strings.ToLower(filepath.FromSlash(file.Path))
		want[rel] = file.Data
		for dir := filepath.Dir(rel); dir != "." && dir != string(filepath.Separator); dir = filepath.Dir(dir) {
			wantDirs[dir] = true
		}
	}
	found := 0
	problem := ""
	walkErr := filepath.WalkDir(folder, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == folder {
			return nil
		}
		rel, err := filepath.Rel(folder, path)
		if err != nil {
			return err
		}
		key := strings.ToLower(rel)
		if entry.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			problem = rel + " is a link"
			return filepath.SkipAll
		}
		if entry.IsDir() {
			if !wantDirs[key] {
				problem = rel + " is not part of the shipped packs"
				return filepath.SkipAll
			}
			return nil
		}
		data, ok := want[key]
		if !ok {
			problem = rel + " is not part of the shipped packs"
			return filepath.SkipAll
		}
		got, err := os.ReadFile(path) // #nosec G304 -- a file under the administrator-only shipped rule pack root.
		if err != nil {
			return err
		}
		if !bytes.Equal(got, data) {
			problem = rel + " is not the file this release ships"
			return filepath.SkipAll
		}
		found++
		return nil
	})
	if walkErr != nil {
		return "the folder cannot be read: " + walkErr.Error()
	}
	if problem != "" {
		return problem
	}
	if found != len(want) {
		return fmt.Sprintf("%d of the %d files this release ships are missing", len(want)-found, len(want))
	}
	if err := windowsShippedRulePacksTreeTrust(folder, "shipped rule packs", serviceAccount); err != nil {
		return "it is not administrator-only: " + err.Error()
	}
	return ""
}

// removeWindowsShippedRulePacksScratch removes the copies an interrupted
// run left in root (.<digest>.new-* and .<digest>.old-*).
func removeWindowsShippedRulePacksScratch(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var notes []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".") || (!strings.Contains(name, ".new-") && !strings.Contains(name, ".old-")) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
			notes = append(notes, fmt.Sprintf("the copy %s an earlier run left stays: %v", filepath.Join(root, name), err))
		}
	}
	return notes
}

// renameWindowsShippedRulePacks renames a folder, retrying for a few
// seconds while another program (an antivirus scan, an indexer) holds a
// file in it.
func renameWindowsShippedRulePacks(from, to string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return err
}

func windowsShippedRulePacksSuffix() (string, error) {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// windowsEnterpriseShippedRulePackProblems names the shipped pack folder the
// config selects (strict or permissive with no policy_dir folder for it)
// when it is missing, holds other files or a standard user can change it:
// the gateway then cannot load the pack. Nil when no shipped pack is
// selected or the folder is this release's copy.
func windowsEnterpriseShippedRulePackProblems(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	selected := ""
	for _, dir := range cfg.ReferencedRulePackDirs() {
		if name := cfg.WindowsShippedRulePackName(dir); name != "" {
			selected = name
			break
		}
	}
	folder := config.WindowsShippedRulePacksFolder()
	if selected == "" || folder == "" {
		return nil
	}
	files, err := policyassets.ShippedRulePackFiles()
	if err != nil {
		return []string{"the rule packs this release ships cannot be read from the binary: " + err.Error()}
	}
	problem := windowsShippedRulePacksProblem(folder, files, strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv)))
	if problem == "" {
		return nil
	}
	return []string{fmt.Sprintf("the config selects the %s rule pack, which this release ships in %s, and %s, so the gateway cannot load it; "+
		"run %s as LocalSystem or from an elevated PowerShell prompt to write it again.%s",
		selected, folder, problem, windowsEnterpriseSetupCommand("/repair", "JSON=1"), windowsEnterpriseSetupSourceNote)}
}

// applyWindowsEnterpriseShippedRulePacks fails status and verify while a
// shipped pack the installed config selects is not this release's copy.
func applyWindowsEnterpriseShippedRulePacks(result *enterprisestatus.Result) {
	if result == nil {
		return
	}
	cfg, err := loadWindowsEnterpriseStandaloneConfig("")
	if err != nil {
		return // status and verify report an unreadable config
	}
	for _, problem := range windowsEnterpriseShippedRulePackProblems(cfg) {
		result.AddError("rule_pack_shipped_invalid", problem)
	}
}

// windowsEnterpriseShippedRulePacksEnsureDrift is the repair a compliant
// ensure still owes a selected shipped pack that is missing or changed:
// PowerShell verify does not check it. A var for tests.
var windowsEnterpriseShippedRulePacksEnsureDrift = func() (reason, detail string) {
	cfg, err := loadWindowsEnterpriseStandaloneConfig("")
	if err != nil {
		return "", ""
	}
	if problems := windowsEnterpriseShippedRulePackProblems(cfg); len(problems) != 0 {
		return "drift:shipped_rule_packs", problems[0]
	}
	return "", ""
}

// applyWindowsStandaloneShippedRulePacksUninstall removes the shipped rule
// pack root after an uninstall that left no deployment. A certification run
// never removes it: the root is the production deployment's, whichever scope
// the run targets, as the scanner runtime's is.
func applyWindowsStandaloneShippedRulePacksUninstall(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if result == nil || result.Action != "uninstall" || len(result.Errors) != 0 ||
		windowsScannerRuntimeCertificationRun(opts) || !windowsEnterpriseIsElevated() || !windowsEnterpriseNoDeploymentLeft() {
		return
	}
	if err := removeWindowsShippedRulePacksRoot(); err != nil {
		result.AddWarning("shipped_rule_packs_left", "the folder of the shipped rule packs could not be removed: "+err.Error())
	}
}

func removeWindowsShippedRulePacksRoot() error {
	root, err := windowsShippedRulePacksRootDir()
	if err != nil {
		return nil
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !strings.EqualFold(filepath.Base(root), productlayout.WindowsRulePacksFolder) {
		return fmt.Errorf("refusing to remove %s: it is not a real folder", root)
	}
	return os.RemoveAll(root)
}
