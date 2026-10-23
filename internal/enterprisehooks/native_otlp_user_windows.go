// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io"
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
// reads or changes another account's file for this row.

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

// windowsManagedUserNativeOTLPAbsent fails while any configuration the
// account's agent reads keeps a DefenseClaw native exporter, or while one
// cannot be checked. The error names fields and sources, never values or
// paths. Verify is read-only and never impersonates.
func windowsManagedUserNativeOTLPAbsent(connectorName, home, dataDir string, sid *windows.SID) error {
	if _, ok := windowsNativeOTLPRoots[connectorName]; !ok {
		return nil
	}
	configs, err := windowsManagedUserNativeOTLPConfigs(connectorName, sid, home, dataDir)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s native OTLP settings: %w", connectorName, err)
	}
	opts := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
	backup, err := readWindowsAccountFile(filepath.Join(dataDir, connector.UserNativeOTLPBackupName(connectorName)), sid, home)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return windowsNativeOTLPUncheckable(connectorName, "the setup backup", err)
	}
	var residue []string
	for _, config := range configs {
		data, err := readWindowsAccountFile(config.path, sid, home)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return windowsNativeOTLPUncheckable(connectorName, config.label, err)
		}
		names, err := connector.UserNativeOTLPResidueIn(connectorName, data, backup, opts)
		if err != nil {
			return fmt.Errorf("enterprise hooks: inspect %s native OTLP settings (%s): %w", connectorName, config.label, err)
		}
		for _, name := range names {
			residue = append(residue, config.label+": "+name)
		}
	}
	credential, err := connector.UserNativeOTLPCredentialResidue(connectorName, opts)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s native OTLP settings: %w", connectorName, err)
	}
	residue = append(residue, credential...)
	if len(residue) > 0 {
		return fmt.Errorf(
			"enterprise hooks: %s keeps a native OTLP exporter from an earlier per-user install (%s); "+
				"the managed gateway does not serve it, so another account could receive its telemetry; repair removes it",
			connectorName,
			strings.Join(residue, ", "),
		)
	}
	return nil
}

func windowsNativeOTLPUncheckable(connectorName, label string, err error) error {
	if errors.Is(err, errWindowsAccountFileNotOwned) {
		return fmt.Errorf(
			"enterprise hooks: %s: %s reaches a file the account does not own, through a link or outside the profile, "+
				"so it cannot be checked for an earlier per-user native OTLP exporter; replace it with the account's own file, "+
				"or remove the link, and the next repair checks it",
			connectorName, label)
	}
	return fmt.Errorf("enterprise hooks: %s: cannot check %s for an earlier per-user native OTLP exporter: %w", connectorName, label, err)
}

// windowsManagedUserNativeOTLPConfigs lists the configuration files of
// connectorName's agent for the account: the one its current root names
// under the profile, the one its persistent CODEX_HOME or CLAUDE_CONFIG_DIR
// names (its own value over the machine's), and the one its per-user setup
// recorded. A variable that does not resolve to a folder fails the check.
func windowsManagedUserNativeOTLPConfigs(connectorName string, sid *windows.SID, home, dataDir string) ([]windowsNativeOTLPConfig, error) {
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
	relocated, err := windowsAccountFolderVariable(sid, home, root.variable)
	if err != nil {
		return nil, err
	}
	if relocated != "" {
		add(filepath.Join(relocated, root.file), root.variable+" "+root.file)
	}
	record, err := readWindowsAccountFile(connector.UserAgentConfigRecordPath(dataDir, connectorName), sid, home)
	switch {
	case err == nil:
		add(connector.UserAgentConfigRecordTarget(connectorName, record), "the recorded "+root.file)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("read the recorded %s location: %w", root.file, err)
	}
	return configs, nil
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
		"USERPROFILE":  home,
		"HOMEDRIVE":    volume,
		"HOMEPATH":     strings.TrimPrefix(home, volume),
		"APPDATA":      filepath.Join(home, "AppData", "Roaming"),
		"LOCALAPPDATA": filepath.Join(home, "AppData", "Local"),
	}
	for _, variable := range windowsAccountMachineWideVariables {
		if machine := os.Getenv(variable); machine != "" {
			vars[strings.ToUpper(variable)] = machine
		}
	}
	if account, _, _, err := sid.LookupAccount(""); err == nil && account != "" {
		vars["USERNAME"] = account
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
// configuration the check reads and then its credential. The caller runs it
// as the target user with the account's home bound (connector.WithUserHomeDir)
// and hardens the data directory afterwards: the atomic edit protects its
// state directory there with the per-user DACL. A file the check may not read
// (errWindowsAccountFileNotOwned) is left as it is, and so is the
// credential: verify keeps the row unverified and names that file.
func removeWindowsManagedUserNativeOTLPAsTarget(connectorName string, sid *windows.SID, home, dataDir string) error {
	if _, ok := windowsNativeOTLPRoots[connectorName]; !ok {
		return nil
	}
	configs, err := windowsManagedUserNativeOTLPConfigs(connectorName, sid, home, dataDir)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s native OTLP settings: %w", connectorName, err)
	}
	opts := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
	complete := true
	for _, config := range configs {
		_, final, err := openWindowsAccountFile(config.path, sid, home)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if errors.Is(err, errWindowsAccountFileNotOwned) {
				complete = false
				continue
			}
			return windowsNativeOTLPUncheckable(connectorName, config.label, err)
		}
		if _, err := connector.RemoveUserNativeOTLPAt(connectorName, final, opts); err != nil {
			return fmt.Errorf("enterprise hooks: remove %s native OTLP exporter from an earlier per-user install (%s): %w",
				connectorName, config.label, err)
		}
	}
	if !complete {
		return nil
	}
	if _, err := connector.RevokeUserNativeOTLPCredential(connectorName, opts); err != nil {
		return fmt.Errorf("enterprise hooks: remove %s native OTLP exporter from an earlier per-user install: %w", connectorName, err)
	}
	return nil
}
