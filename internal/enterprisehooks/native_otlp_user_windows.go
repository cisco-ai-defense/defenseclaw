// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The Windows managed profile delivers Codex and Claude Code through machine
// policy and serves them from the gateway service; it writes no native OTLP
// exporter into the account's own agent configuration. An exporter an earlier
// per-user install left there still names that install's port. No DefenseClaw
// process of the account holds that port, so another account can bind it and
// receive the agent's prompt telemetry and bearer (GAP-0836). Verify reports
// such an exporter so the guardian's next reconcile, including the one at
// service start, repairs the row; install removes it as the target user.
//
// The exporter can be in any configuration the agent reads, not only the one
// under the profile: the account's CODEX_HOME or CLAUDE_CONFIG_DIR moves it,
// and the per-user setup recorded the file it changed (GAP-0928). A path may
// pass through a link; the check follows it as the agent does and judges the
// file it reaches (GAP-0929), but reads a file outside the profile, or one it
// reaches through a link, only when the account owns it: the guardian never
// reads or changes another account's file for this row. AppData that User
// Shell Folders redirects to a share, a share a variable names, and the
// account's mapped drives are the account's folders too: verify reads a file
// there under the account's own token, as the service would reach a share as
// the computer and has none of the account's drive mappings.
//
// The check never blocks the account's hooks: a configuration it cannot
// read or resolve (a hive or share that is unavailable, a signed-out account,
// a file another owner holds) and an exporter on a share repair cannot edit
// durably are warnings, never a failed row (a failed row leaves the account
// unprotected and its hooks closed). Repair always revokes the credential,
// so an exporter the guardian could not remove sends no DefenseClaw
// credential to the holder of its port.
//
// An exporter repair could not remove (on a share, or in a configuration it
// could not read or edit as the account) leaves the take-back-pending marker
// in the account's data directory before the credential is revoked; the
// marker keeps the credential's digest, so a later take-back still knows the
// exporter as DefenseClaw's. Status and verify report the account while the
// marker is there (connector.AgentConfigNativeOTLPTakeBackPending), the
// guardian runs the take-back again, and the take-back clears the marker only
// once it read every configuration and found no exporter (GAP-1839,
// GAP-1840, GAP-1170). A configuration behind a link whose target cannot be
// reached reads as absent, but it was not read, so it never clears the marker
// (GAP-2095).

// windowsNativeOTLPConfig is one configuration file the check reads and how
// messages name it (never by the account's path or its values).
type windowsNativeOTLPConfig struct {
	path  string
	label string
}

// windowsNativeOTLPRoots are the variables that move each agent's
// configuration root and the file under it.
var windowsNativeOTLPRoots = map[string]struct{ variable, file string }{
	"codex":      {"CODEX_HOME", "config.toml"},
	"claudecode": {"CLAUDE_CONFIG_DIR", "settings.json"},
}

// errWindowsAccountFileNotOwned marks a configuration the check reached
// through a link or outside the profile that the account does not own.
var errWindowsAccountFileNotOwned = errors.New("the file is not the account's own")

// windowsNativeOTLPWarn reports what the check could not do for a row
// (replaceable in tests). The message names fields and sources, never values
// or paths.
var windowsNativeOTLPWarn = func(message string) {
	fmt.Fprintf(os.Stderr, "[enterprise-hooks] WARN %s\n", message)
}

// windowsManagedUserNativeOTLPAbsent fails while a configuration the
// account's agent reads keeps a DefenseClaw native exporter repair can
// remove, or while the credential of an earlier per-user install remains:
// the guardian's repair then removes them. Every configuration it cannot
// check, and an exporter on a share, is a warning (windowsNativeOTLPWarn).
// The error names fields and sources, never values or paths. Verify is
// read-only and never impersonates.
func windowsManagedUserNativeOTLPAbsent(connectorName, home, dataDir string, sid *windows.SID, served ...string) error {
	_, err := windowsManagedUserNativeOTLPCheck(connectorName, home, dataDir, sid, served...)
	return err
}

// windowsManagedUserNativeOTLPCheck is windowsManagedUserNativeOTLPAbsent
// that also returns what the row reports: connector.AgentConfigNativeOTLPUnchecked
// when a configuration reaches a file the account does not own (GAP-0929),
// which the status and verify name with its remedy, else "".
//
// served are the addresses the managed gateway serves (API, guardrail
// proxy): an exporter with the managed orphan shape on any other loopback
// port is the product's (GAP-0836, connector.UserNativeOTLPMarkedOrphanIn).
func windowsManagedUserNativeOTLPCheck(connectorName, home, dataDir string, sid *windows.SID, served ...string) (string, error) {
	if _, ok := windowsNativeOTLPRoots[connectorName]; !ok {
		return "", nil
	}
	opts := windowsManagedNativeOTLPOpts(dataDir, served)
	var residue, onShare []string
	founds, notOwned, _ := windowsManagedUserNativeOTLPResidue(connectorName, sid, home, dataDir, readWindowsAccountConfig, false, served...)
	report := ""
	if notOwned {
		report = connector.AgentConfigNativeOTLPUnchecked
	}
	for _, found := range founds {
		if windowsShareFinalPath(found.final) {
			onShare = append(onShare, found.label)
			continue
		}
		for _, name := range found.names {
			residue = append(residue, found.label+": "+name)
		}
	}
	if len(onShare) > 0 {
		windowsNativeOTLPWarn(fmt.Sprintf(
			"enterprise hooks: %s keeps a native OTLP exporter from an earlier per-user install in %s on a network share, "+
				"which repair cannot edit durably; remove the exporter there by hand (its DefenseClaw credential is revoked)",
			connectorName, strings.Join(onShare, ", ")))
	}
	credential, err := connector.UserNativeOTLPCredentialResidue(connectorName, opts)
	if err != nil {
		windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: inspect %s native OTLP credential: %v", connectorName, err))
	}
	residue = append(residue, credential...)
	if len(residue) > 0 {
		return report, fmt.Errorf(
			"enterprise hooks: %s keeps a native OTLP exporter from an earlier per-user install (%s); "+
				"the managed gateway does not serve it, so another account could receive its telemetry; repair removes it",
			connectorName,
			strings.Join(residue, ", "),
		)
	}
	return report, nil
}

// windowsNativeOTLPFound is a configuration that keeps the exporter: its
// label, the final path read and the exporter entries; marked reports one
// only the managed orphan shape proves, with data the bytes read.
type windowsNativeOTLPFound struct {
	label, final string
	names        []string
	marked       bool
	data         []byte
}

// windowsManagedNativeOTLPOpts are the SetupOpts every managed native OTLP
// check and take-back judges with: the managed orphan shape on (GAP-0836,
// LEAD DECISION 05:36 option (a)) with the addresses the gateway serves.
func windowsManagedNativeOTLPOpts(dataDir string, served []string) connector.SetupOpts {
	return connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: true, ManagedMarkedOrphanExporters: true, ManagedServedAddrs: served}
}

// windowsManagedUserNativeOTLPResidue resolves the account's configurations
// once and returns those that keep a DefenseClaw exporter, read with read,
// whether one reaches a file the account does not own, and whether any
// configuration could not be checked. What it cannot resolve or read is a
// warning. The take-back (takeBack) also knows an exporter by the revoked
// credential's digest a pending marker keeps, and counts a configuration
// behind a link whose target cannot be reached as unchecked; the reason is
// returned in unreachable, not warned, since an account with nothing to take
// back has nothing to report.
func windowsManagedUserNativeOTLPResidue(
	connectorName string,
	sid *windows.SID,
	home, dataDir string,
	read func(string, *windows.SID, string) ([]byte, string, error),
	takeBack bool,
	served ...string,
) (found []windowsNativeOTLPFound, notOwned bool, unchecked []string) {
	configs, problems := windowsManagedUserNativeOTLPConfigs(connectorName, sid, home, dataDir)
	for _, problem := range problems {
		windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: inspect %s native OTLP settings: %v", connectorName, problem))
		unchecked = append(unchecked, "a configuration folder could not be resolved")
	}
	opts := windowsManagedNativeOTLPOpts(dataDir, served)
	backup, err := readWindowsAccountFile(filepath.Join(dataDir, connector.UserNativeOTLPBackupName(connectorName)), sid, home)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// Without the backup an operator entry cannot be told from
		// DefenseClaw's, so no configuration is judged.
		windowsNativeOTLPWarn(windowsNativeOTLPUncheckable(connectorName, "the setup backup", err))
		return nil, false, append(unchecked, "the setup backup could not be read")
	}
	residueIn := connector.UserNativeOTLPResidueIn
	if takeBack {
		residueIn = connector.UserNativeOTLPTakeBackResidueIn
	}
	for _, config := range configs {
		data, final, err := read(config.path, sid, home)
		if errors.Is(err, os.ErrNotExist) {
			if takeBack && connector.UserNativeOTLPPathUnreachable(config.path) != "" {
				unchecked = append(unchecked, config.label+" is behind a link whose target cannot be reached")
			}
			continue
		}
		if err != nil {
			notOwned = notOwned || errors.Is(err, errWindowsAccountFileNotOwned)
			windowsNativeOTLPWarn(windowsNativeOTLPUncheckable(connectorName, config.label, err))
			unchecked = append(unchecked, config.label+" could not be read")
			continue
		}
		names, err := residueIn(connectorName, data, backup, opts)
		if err != nil {
			windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: inspect %s native OTLP settings (%s): %v", connectorName, config.label, err))
			unchecked = append(unchecked, config.label+" could not be parsed")
			continue
		}
		if !takeBack {
			// Option (b): an exporter with DefenseClaw markers that nothing
			// proves is the product's stays, and Verify names it.
			if kept := connector.UserNativeOTLPMarkedKeptIn(connectorName, data, backup, opts); len(kept) > 0 {
				windowsNativeOTLPWarn(fmt.Sprintf(
					"enterprise hooks: %s: %s keeps %s with DefenseClaw x-defenseclaw-* headers that this install cannot prove are its own, "+
						"so it is kept; if the account did not add it, remove those entries as that user (the agent sends its telemetry there)",
					connectorName, config.label, strings.Join(kept, ", ")))
			}
		}
		if len(names) > 0 {
			found = append(found, windowsNativeOTLPFound{label: config.label, final: final, names: names,
				marked: connector.UserNativeOTLPMarkedOrphanIn(connectorName, data, opts), data: data})
		}
	}
	return found, notOwned, unchecked
}

// keepWindowsNativeOTLPCopy keeps data (the configuration as read) beside
// final with connector.NativeOTLPMarkedOrphanBackupSuffix and returns its
// path. It never writes over an existing file: a numbered copy that already
// holds exactly data (an earlier take-back the edit refused) is reused, and
// created reports whether this call wrote the file. It runs as the account.
func keepWindowsNativeOTLPCopy(final string, data []byte) (path string, created bool, err error) {
	path = final + connector.NativeOTLPMarkedOrphanBackupSuffix
	for attempt := 0; ; attempt++ {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			if windowsNativeOTLPCopyHolds(path, data) {
				return path, false, nil
			}
			if attempt < 8 {
				path = fmt.Sprintf("%s.%d%s", final, attempt+1, connector.NativeOTLPMarkedOrphanBackupSuffix)
				continue
			}
		}
		if err != nil {
			return "", false, err
		}
		_, err = file.Write(data)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
			return "", false, err
		}
		return path, true, nil
	}
}

// windowsNativeOTLPCopyHolds reports whether path is a regular file (not a
// link) that holds exactly data.
func windowsNativeOTLPCopyHolds(path string, data []byte) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(data)) {
		return false
	}
	held, err := os.ReadFile(path)
	return err == nil && string(held) == string(data)
}

// discardWindowsNativeOTLPCopy removes the copy this take-back wrote when the
// edit it was kept for was refused and the configuration still holds exactly
// what was copied, so a refusal that repeats every guardian cycle leaves no
// new copy each time (GAP-2568).
func discardWindowsNativeOTLPCopy(copyPath, final string, data []byte) {
	if windowsNativeOTLPCopyHolds(final, data) {
		_ = os.Remove(copyPath)
	}
}

// windowsRemoveUserNativeOTLPAt is the edit of one configuration
// (replaceable in tests).
var windowsRemoveUserNativeOTLPAt = connector.RemoveUserNativeOTLPAt

// windowsNativeOTLPUncheckable is the warning for a configuration the check
// could not read. A path error keeps only its cause: the warning names the
// source, never the path.
func windowsNativeOTLPUncheckable(connectorName, label string, err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	if errors.Is(err, errWindowsAccountFileNotOwned) {
		return fmt.Sprintf(
			"enterprise hooks: %s: %s reaches a file the account does not own, through a link or outside the profile, "+
				"so it cannot be checked for an earlier per-user native OTLP exporter; replace it with the account's own file, "+
				"or remove the link, and the next repair checks it",
			connectorName, label)
	}
	if errors.Is(err, errWindowsAccountConfigNeedsSession) {
		return fmt.Sprintf(
			"enterprise hooks: %s: %s is on a share or a drive only the account has, so it is checked as the account, "+
				"and the account has no signed-in session now; the next repair after the account signs in checks it: %v",
			connectorName, label, err)
	}
	return fmt.Sprintf("enterprise hooks: %s: cannot check %s for an earlier per-user native OTLP exporter: %v", connectorName, label, err)
}

// windowsManagedUserNativeOTLPConfigs lists the configuration files of
// connectorName's agent for the account: the one its current root names
// under the profile, the one its persistent CODEX_HOME or CLAUDE_CONFIG_DIR
// names (its own value over the machine's), and the one its per-user setup
// recorded. A variable that does not resolve to a folder, or a record that
// cannot be read, is a problem; the other configurations are still listed.
func windowsManagedUserNativeOTLPConfigs(connectorName string, sid *windows.SID, home, dataDir string) ([]windowsNativeOTLPConfig, []error) {
	root := windowsNativeOTLPRoots[connectorName]
	var configs []windowsNativeOTLPConfig
	seen := map[string]bool{}
	add := func(path, label string) {
		key := strings.ToLower(filepath.Clean(path))
		if path == "" || seen[key] {
			return
		}
		seen[key] = true
		configs = append(configs, windowsNativeOTLPConfig{path: filepath.Clean(path), label: label})
	}
	add(connector.UserNativeOTLPConfigPathFor(connectorName, home), root.file)
	var problems []error
	relocated, err := windowsAccountFolderVariable(sid, home, root.variable)
	switch {
	case err != nil:
		problems = append(problems, err)
	case relocated != "":
		add(filepath.Join(relocated, root.file), root.variable+" "+root.file)
	}
	record, err := readWindowsAccountFile(connector.UserAgentConfigRecordPath(dataDir, connectorName), sid, home)
	switch {
	case err == nil:
		add(connector.UserAgentConfigRecordTarget(connectorName, record), "the recorded "+root.file)
	case !errors.Is(err, os.ErrNotExist):
		problems = append(problems, fmt.Errorf("read the recorded %s location: %w", root.file, err))
	}
	return configs, problems
}

// windowsMachineEnvironment reads a value of the machine environment
// (HKLM\...\Session Manager\Environment), "" when unset. Replaceable in tests.
var windowsMachineEnvironment = func(name string) string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return value
}

// windowsAccountMachineWideVariables are machine-wide variables Windows puts
// in every account's environment; the service's own values are the machine's.
var windowsAccountMachineWideVariables = []string{
	"SystemRoot", "SystemDrive", "windir", "ProgramData", "ALLUSERSPROFILE", "PUBLIC",
	"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
}

// windowsAccountUserShellFolderValue reads the account's effective AppData
// root from its loaded profile hive. A signed-out account has no running
// agent; until its hive is loaded, verification must stay unverified rather
// than guess the profile's default folder.
var windowsAccountUserShellFolderValue = func(sid *windows.SID, name string) (string, error) {
	key, err := registry.OpenKey(registry.USERS, sid.String()+`\`+windowsUserShellFoldersKey, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	return value, err
}

// windowsAccountVolatileEnvironment reads a value sign-in set in the
// account's logon environment (HKU\<sid>\Volatile Environment), "" when
// unset or while the account is signed out. Replaceable in tests.
var windowsAccountVolatileEnvironment = func(sid *windows.SID, name string) string {
	key, err := registry.OpenKey(registry.USERS, sid.String()+`\Volatile Environment`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return value
}

// windowsAccountShellFolder is the folder a User Shell Folders value names
// for the account: the profile's defaultRel folder when it is empty, else the
// value with the account's variables (vars) expanded as for its processes.
// Unlike the IDE inventory (RedirectedAppDataFolder), a share is the
// account's folder here: its agent reads its configuration there, and verify
// reads it as the account (readWindowsAccountConfig).
func windowsAccountShellFolder(raw string, vars map[string]string, home, defaultRel string) (folder, refused string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return filepath.Join(home, defaultRel), ""
	}
	value := expandWindowsAccountVariables(raw, vars)
	if strings.Contains(value, "%") {
		return "", "names a variable the account's processes do not set"
	}
	return windowsAbsoluteFolder(value, true)
}

// windowsAccountConfigReadAs runs fn under the token of the account's
// signed-in session (replaceable in tests).
var windowsAccountConfigReadAs = withWindowsEnterpriseSessionImpersonation

// windowsDriveType is GetDriveType of a drive root (replaceable in tests).
var windowsDriveType = func(root string) uint32 {
	ptr, err := winpath.UTF16Ptr(root)
	if err != nil {
		return windows.DRIVE_UNKNOWN
	}
	return windows.GetDriveType(ptr)
}

// errWindowsAccountConfigNeedsSession marks a configuration only the
// account's own token reads as its agent does, while that token is not
// available.
var errWindowsAccountConfigNeedsSession = errors.New("the file is read as the account and the account has no signed-in session")

// readWindowsAccountConfig is readWindowsAccountFile for verify, which runs
// as the service. A configuration on a share, on a drive the service does
// not have as the account has it (a mapped drive), or one the service is
// refused, is read under the account's own token instead: the service would
// reach a share as the computer, and has none of the account's drive
// mappings, so it would judge another file than the agent reads, or none.
// The same bounds and ownership rule apply.
// It also returns the final path of the file read (openWindowsAccountFile).
func readWindowsAccountConfig(path string, sid *windows.SID, home string) ([]byte, string, error) {
	if !windowsAccountOnlyPath(path) {
		data, final, err := openWindowsAccountFile(path, sid, home)
		if !windowsServiceRefused(err) {
			return data, final, err
		}
	}
	var data []byte
	var final string
	var readErr error
	if err := windowsAccountConfigReadAs(sid, home, func() error {
		data, final, readErr = openWindowsAccountFile(path, sid, home)
		return nil
	}); err != nil {
		return nil, "", fmt.Errorf("%w: %v", errWindowsAccountConfigNeedsSession, err)
	}
	return data, final, readErr
}

// windowsShareFinalPath reports a final path (windowsHandleFinalPath) on a
// network share, which the compare-and-swap edit refuses: it cannot order
// its writes durably over SMB.
func windowsShareFinalPath(final string) bool {
	return strings.HasPrefix(final, `\\`)
}

// windowsAccountOnlyPath reports a path the service cannot read as the
// account would: one on a share or any other non-drive volume, or on a drive
// letter that is remote or missing for the service.
func windowsAccountOnlyPath(path string) bool {
	drive := filepath.VolumeName(path)
	if len(drive) == 6 && (strings.HasPrefix(drive, `\\?\`) || strings.HasPrefix(drive, `\\.\`)) {
		drive = drive[4:]
	}
	if len(drive) != 2 || drive[1] != ':' || !isASCIIDriveLetter(drive[0]) {
		return true
	}
	switch windowsDriveType(drive + `\`) {
	case windows.DRIVE_REMOTE, windows.DRIVE_NO_ROOT_DIR, windows.DRIVE_UNKNOWN:
		return true
	}
	return false
}

// windowsServiceRefused reports a read the service was refused, or that
// reached a share the service cannot sign in to, as through a link.
func windowsServiceRefused(err error) bool {
	if err == nil {
		return false
	}
	for _, refused := range []error{
		os.ErrPermission, windows.ERROR_BAD_NETPATH, windows.ERROR_BAD_NET_NAME,
		windows.ERROR_NETWORK_ACCESS_DENIED, windows.ERROR_LOGON_FAILURE,
	} {
		if errors.Is(err, refused) {
			return true
		}
	}
	return false
}

// windowsAccountFolderVariable resolves the folder a variable of the
// account's persistent environment names, the account's own value over the
// machine's ("" when neither sets it). The profile variables, the
// machine-wide ones, the account's name and a leading ~ expand as they do
// for the account's processes; a value that still names a variable or is not
// absolute fails, since the folder the agent reads cannot be told.
func windowsAccountFolderVariable(sid *windows.SID, home, name string) (string, error) {
	value := strings.TrimSpace(windowsUserEnvironment(sid.String(), name))
	if value == "" {
		value = strings.TrimSpace(windowsMachineEnvironment(name))
	}
	if value == "" {
		return "", nil
	}
	home = filepath.Clean(home)
	volume := filepath.VolumeName(home)
	vars := map[string]string{
		"USERPROFILE": home,
		"HOMEDRIVE":   volume,
		"HOMEPATH":    strings.TrimPrefix(home, volume),
	}
	for _, variable := range windowsAccountMachineWideVariables {
		if machine := os.Getenv(variable); machine != "" {
			vars[strings.ToUpper(variable)] = machine
		}
	}
	account, _, _, err := sid.LookupAccount("")
	if err == nil && account != "" {
		vars["USERNAME"] = account
	}
	// Sign-in sets the home folder variables from the account's home folder,
	// which may be on a share (HOMESHARE).
	for _, variable := range []string{"HOMEDRIVE", "HOMEPATH", "HOMESHARE"} {
		if session := strings.TrimSpace(windowsAccountVolatileEnvironment(sid, variable)); session != "" {
			vars[variable] = session
		}
	}
	for _, folder := range []struct {
		variable, shellName, defaultRel string
	}{
		{"APPDATA", "AppData", `AppData\Roaming`},
		{"LOCALAPPDATA", "Local AppData", `AppData\Local`},
	} {
		if !strings.Contains(strings.ToUpper(value), "%"+folder.variable+"%") {
			continue
		}
		raw, err := windowsAccountUserShellFolderValue(sid, folder.shellName)
		if err != nil {
			return "", fmt.Errorf("the account's %s folder cannot be determined for %s", folder.variable, name)
		}
		redirected, refused := windowsAccountShellFolder(raw, vars, home, folder.defaultRel)
		if refused != "" {
			return "", fmt.Errorf("the account's %s folder cannot be checked for %s: %s", folder.variable, name, refused)
		}
		vars[folder.variable] = redirected
	}
	value = expandWindowsAccountVariables(value, vars)
	switch {
	case value == "~":
		value = home
	case strings.HasPrefix(value, `~\`) || strings.HasPrefix(value, "~/"):
		value = filepath.Join(home, value[2:])
	}
	if strings.Contains(value, "%") || !filepath.IsAbs(value) {
		return "", fmt.Errorf("the account's %s does not name an absolute folder; set it to one", name)
	}
	return filepath.Clean(value), nil
}

// expandWindowsAccountVariables expands %NAME% references against vars, as
// ExpandEnvironmentStrings does: names are case-insensitive and an unknown
// reference is kept.
func expandWindowsAccountVariables(value string, vars map[string]string) string {
	var out strings.Builder
	for {
		start := strings.IndexByte(value, '%')
		if start < 0 {
			break
		}
		end := strings.IndexByte(value[start+1:], '%')
		if end < 0 {
			break
		}
		end += start + 1
		if replacement, ok := vars[strings.ToUpper(value[start+1:end])]; ok && end > start+1 {
			out.WriteString(value[:start])
			out.WriteString(replacement)
			value = value[end+1:]
			continue
		}
		out.WriteString(value[:end])
		value = value[end:]
	}
	out.WriteString(value)
	return out.String()
}

// readWindowsAccountFile reads a file of the account's for the check, at
// most connector.UserNativeOTLPReadLimit bytes, following links as the
// agent does. A file inside the profile reached without a link is read as
// it is; any other file only when the account owns the file the path
// reaches (errWindowsAccountFileNotOwned otherwise). A missing file keeps
// os.ErrNotExist.
func readWindowsAccountFile(path string, sid *windows.SID, home string) ([]byte, error) {
	data, _, err := openWindowsAccountFile(path, sid, home)
	return data, err
}

// openWindowsAccountFile is readWindowsAccountFile that also returns the
// final path of the file read, with every link resolved: repair edits that
// file, which keeps the account's link in place (the compare-and-swap edit
// refuses a path through a reparse point).
func openWindowsAccountFile(path string, sid *windows.SID, home string) ([]byte, string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, "", os.ErrNotExist
	}
	name := filepath.Base(path)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", os.ErrNotExist
		}
		return nil, "", fmt.Errorf("inspect %s: %w", name, err)
	}
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, "", err
	}
	handle, err := windows.CreateFile(ptr, windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, "", os.ErrNotExist
	}
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", name, err)
	}
	file := os.NewFile(uintptr(handle), name)
	defer file.Close()
	if kind, err := windows.GetFileType(handle); err != nil || kind != windows.FILE_TYPE_DISK {
		return nil, "", fmt.Errorf("%s is not a regular file", name)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, "", fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > connector.UserNativeOTLPReadLimit {
		return nil, "", connector.UserNativeOTLPFileTooLarge(name)
	}
	if rejectWindowsReparseChain(path) != nil || !windowsPathWithin(home, path) {
		owner, err := windowsHandleOwner(handle)
		if err != nil {
			return nil, "", fmt.Errorf("read the owner of %s: %w", name, err)
		}
		if sid == nil || !owner.Equals(sid) {
			return nil, "", errWindowsAccountFileNotOwned
		}
	}
	final, err := windowsHandleFinalPath(handle)
	if err != nil {
		return nil, "", fmt.Errorf("resolve %s: %w", name, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, connector.UserNativeOTLPReadLimit+1))
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(data)) > connector.UserNativeOTLPReadLimit {
		return nil, "", connector.UserNativeOTLPFileTooLarge(name)
	}
	return data, final, nil
}

// windowsHandleFinalPath is the normalized DOS path of the file an open
// handle names, every link resolved.
func windowsHandleFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0) // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
	if err != nil {
		return "", err
	}
	if int(n) >= len(buffer) {
		return "", errors.New("the final path is too long")
	}
	final := windows.UTF16ToString(buffer[:n])
	switch {
	case strings.HasPrefix(final, `\\?\UNC\`):
		final = `\\` + final[len(`\\?\UNC\`):]
	case strings.HasPrefix(final, `\\?\`):
		final = final[len(`\\?\`):]
	}
	return final, nil
}

// removeWindowsManagedUserNativeOTLPAsTarget removes that exporter from every
// configuration the check reads and revokes its credential. The caller runs
// it as the target user with the account's home bound
// (connector.WithUserHomeDir) and hardens the data directory afterwards: the
// atomic edit protects its state directory there with the per-user DACL. It
// never fails the row: a configuration it cannot read or edit (another
// owner's file, a share the compare-and-swap edit refuses, an unavailable
// folder) is left as it is with a warning, and the credential is revoked in
// every case, so no exporter the guardian left sends it to another account.
// An exporter it left, or a configuration it could not check for an account
// with an earlier per-user install to take back, keeps the take-back-pending
// marker; it is cleared only once every configuration was checked and none
// keeps an exporter (GAP-1839, GAP-1840, GAP-2095).
func removeWindowsManagedUserNativeOTLPAsTarget(connectorName string, sid *windows.SID, home, dataDir string, served ...string) {
	if _, ok := windowsNativeOTLPRoots[connectorName]; !ok {
		return
	}
	opts := windowsManagedNativeOTLPOpts(dataDir, served)
	founds, _, unchecked := windowsManagedUserNativeOTLPResidue(connectorName, sid, home, dataDir, openWindowsAccountFile, true, served...)
	var kept []string
	for _, found := range founds {
		if windowsShareFinalPath(found.final) {
			windowsNativeOTLPWarn(fmt.Sprintf(
				"enterprise hooks: %s: %s on a network share keeps a native OTLP exporter from an earlier per-user install; "+
					"repair cannot edit a share durably, so remove the exporter there by hand", connectorName, found.label))
			kept = append(kept, found.label+" is on a network share")
			continue
		}
		copyPath, copyCreated := "", false
		if found.marked {
			// Only its markers and port prove this exporter, so the file is
			// kept as it was before it is edited (GAP-0836).
			path, created, err := keepWindowsNativeOTLPCopy(found.final, found.data)
			if err != nil {
				windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: %s: keep a copy of %s before removing its native OTLP exporter: %v",
					connectorName, found.label, err))
				kept = append(kept, found.label+" could not be copied before the edit")
				continue
			}
			copyPath, copyCreated = path, created
		}
		if _, err := windowsRemoveUserNativeOTLPAt(connectorName, found.final, opts); err != nil {
			if copyCreated {
				discardWindowsNativeOTLPCopy(copyPath, found.final, found.data)
			}
			windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: remove %s native OTLP exporter from an earlier per-user install (%s): %v",
				connectorName, found.label, err))
			kept = append(kept, found.label+" could not be edited")
			continue
		}
		if copyPath != "" {
			windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: %s: removed the native OTLP exporter of an earlier per-user install from %s "+
				"(DefenseClaw markers, a loopback port the managed gateway does not serve: %s); a copy of the file is beside it",
				connectorName, found.label, strings.Join(found.names, ", ")))
			if err := connector.RecordNativeOTLPMarkedOrphanRemoved(dataDir, connectorName, copyPath); err != nil {
				windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: %s: the removal could not be recorded for status and verify: %v", connectorName, err))
			}
		}
	}
	credential, _ := connector.UserNativeOTLPCredentialResidue(connectorName, opts)
	earlier := len(credential) > 0 || connector.NativeOTLPTakeBackPending(dataDir, connectorName)
	switch {
	case len(kept) > 0 || (len(unchecked) > 0 && earlier):
		// The marker keeps the credential's digest, so it is written before
		// the credential is revoked.
		reasons := strings.Join(append(kept, unchecked...), "; ")
		if err := connector.RecordNativeOTLPTakeBackPending(dataDir, connectorName); err != nil {
			windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: %s native OTLP take-back is not finished (%s), and it could not be recorded for status and verify: %v",
				connectorName, reasons, err))
		} else {
			windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: %s native OTLP take-back is not finished (%s); status and verify report it until a later repair finds no exporter",
				connectorName, reasons))
		}
	case len(unchecked) == 0:
		if err := connector.ClearNativeOTLPTakeBackPending(dataDir, connectorName); err != nil {
			windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: %s native OTLP exporter is gone, but its take-back-pending marker could not be removed (%v); status keeps reporting it until repair removes it",
				connectorName, err))
		}
	}
	if _, err := connector.RevokeUserNativeOTLPCredential(connectorName, opts); err != nil {
		windowsNativeOTLPWarn(fmt.Sprintf("enterprise hooks: revoke %s native OTLP credential from an earlier per-user install: %v", connectorName, err))
	}
}
