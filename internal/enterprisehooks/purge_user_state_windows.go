// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// PurgeWindowsUserState removes one enrolled account's whole DefenseClaw
// per-user folder (%USERPROFILE%\.defenseclaw) for the standalone Windows
// uninstall with purge, after the uninstall committed and removed the
// registrations it could. It runs as LocalSystem, whether or not the account
// is signed in: some of the folder's subfolders grant only the account and
// SYSTEM, not Administrators. Like the Unix purge it removes everything,
// DefenseClaw's hook scripts, the per-user hook tokens and the account's own
// hooks the foreign-hook policy moved aside included (see
// connector.PurgeUserStateInRoot). Anything a failure leaves goes back to a
// DACL the account can manage. A missing folder is not an error.
func PurgeWindowsUserState(rawHome, rawSID, rawDataDir string) error {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	home, sid, err := validateWindowsEnterpriseHome(rawHome, rawSID)
	if err != nil {
		return err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, rawDataDir)
	if err != nil {
		return err
	}
	failures := []error{purgeWindowsUserStateFolder(home, sid, dataDir)}
	// A rolled-back enrollment can keep a copy of the folder aside as
	// .defenseclaw.rollback-<random> beside it; that is DefenseClaw per-user
	// data too (GAP-1567).
	kept, err := windowsUserStateRollbackFolders(home)
	failures = append(failures, err)
	for _, folder := range kept {
		failures = append(failures, purgeWindowsUserStateFolder(home, sid, folder))
	}
	return errors.Join(failures...)
}

// windowsUserStateRollbackFolders lists the .defenseclaw.rollback-<random>
// folders a rolled-back enrollment kept in home.
func windowsUserStateRollbackFolders(home string) ([]string, error) {
	entries, err := os.ReadDir(home)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var folders []string
	for _, entry := range entries {
		random, found := strings.CutPrefix(entry.Name(), windowsManagedRuntimeRollbackPrefix)
		if !found || len(random) != 2*windowsManagedRuntimeStageRandomBytes || strings.Trim(random, "0123456789abcdef") != "" {
			continue
		}
		folders = append(folders, filepath.Join(home, entry.Name()))
	}
	return folders, nil
}

// purgeWindowsUserStateFolder removes one DefenseClaw per-user folder of the
// account (see PurgeWindowsUserState).
func purgeWindowsUserStateFolder(home string, sid *windows.SID, dataDir string) error {
	info, err := os.Lstat(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("enterprise hooks: refusing to purge %s, which is not a plain folder", dataDir)
	}
	// The account can rename or replace its own folder. A handle that does
	// not share delete access keeps it from doing so while the purge runs,
	// and the root must be the folder that handle holds.
	pin, err := openWindowsUserStatePin(dataDir)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		pin.Close()
		return err
	}
	purgeErr := func() error {
		pinned, err := pin.Stat()
		if err != nil {
			return err
		}
		opened, err := root.Stat(".")
		if err != nil {
			return err
		}
		if !pinned.IsDir() || pinned.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !os.SameFile(pinned, opened) {
			return fmt.Errorf("enterprise hooks: refusing to purge %s, which changed while it was opened", dataDir)
		}
		return connector.PurgeUserStateInRoot(root, func(rel string) error {
			return removeWindowsUserStateDenied(windows.Handle(pin.Fd()), rel)
		})
	}()
	root.Close()
	pin.Close()
	// Gone only when nothing stayed. Remove takes only an empty folder, and
	// a link put in its place only as the link itself.
	_ = os.Remove(dataDir)
	return errors.Join(purgeErr, relaxWindowsKeptUserState(home, sid, dataDir))
}

// relaxWindowsKeptUserState returns what the purge kept to the owner-private
// shape the per-user CLI keeps (LocalSystem and OWNER RIGHTS full control).
// The managed DACL's read-only OWNER RIGHTS entry denies the account
// WRITE_DAC, so a later per-user install could not protect its own folder and
// its first run failed with Access is denied. Only objects the account owns
// that carry that entry change, and a reparse point is neither followed nor
// changed.
func relaxWindowsKeptUserState(home string, sid *windows.SID, dataDir string) error {
	if _, err := os.Lstat(dataDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	target := windowsGenericManagedTarget{home: home, sid: sid, dataDir: dataDir}
	var failures []error
	walkErr := filepath.WalkDir(dataDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			failures = append(failures, err)
			return nil
		}
		switch {
		case entry.IsDir():
			_, err = relaxWindowsStandalonePerUserDirectory(target, path)
		case entry.Type().IsRegular():
			_, err = relaxWindowsStandalonePerUserTokenFile(target, path)
		}
		if err != nil {
			failures = append(failures, err)
		}
		return nil
	})
	return errors.Join(walkErr, errors.Join(failures...))
}

// removeWindowsUserStateDenied removes rel, a path under the pinned folder
// whose access list refuses LocalSystem: the account owns its folder and can
// deny SYSTEM on a subfolder. SeBackupPrivilege and SeRestorePrivilege with
// backup intent grant the access that list refuses, so no owner or access
// list has to change first. Every open is relative to a handle already held
// and opens a reparse point itself, so a link is removed, never followed.
func removeWindowsUserStateDenied(pin windows.Handle, rel string) error {
	parts := strings.Split(rel, `\`)
	return runWindowsManagedRuntimeSetupPrivilege(func() error {
		parent := pin
		defer func() {
			if parent != pin {
				_ = windows.CloseHandle(parent)
			}
		}()
		for _, part := range parts[:len(parts)-1] {
			next, err := openWindowsNamespacePurgeChild(
				parent, part,
				windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
				true,
				windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			)
			if windowsNamespacePurgeChildMissing(err) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("enterprise hooks: open %s without following: %w", part, err)
			}
			if parent != pin {
				_ = windows.CloseHandle(parent)
			}
			parent = next
			attributes, err := windowsQuarantineHandleAttributes(parent)
			if err != nil {
				return err
			}
			if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				return fmt.Errorf("enterprise hooks: refusing to purge under %s, which is a link", part)
			}
		}
		child, err := openWindowsUserStateDeniedChild(parent, parts[len(parts)-1])
		if windowsNamespacePurgeChildMissing(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("enterprise hooks: open %s without following: %w", rel, err)
		}
		purgeErr := purgeWindowsQuarantineHandle(child, 0, &windowsQuarantineBudget{}, openWindowsUserStateDeniedChild)
		closeErr := windows.CloseHandle(child)
		if purgeErr != nil {
			return fmt.Errorf("enterprise hooks: remove %s with backup intent: %w", rel, purgeErr)
		}
		return closeErr
	})
}

func openWindowsUserStateDeniedChild(parent windows.Handle, name string) (windows.Handle, error) {
	return openWindowsNamespacePurgeChild(
		parent, name,
		windows.DELETE|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES|windows.SYNCHRONIZE,
		false,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
	)
}

// openWindowsUserStatePin opens the folder itself, not what a reparse point
// in its place would name, without sharing delete access. It can list the
// folder, so removeWindowsUserStateDenied can open entries relative to it.
func openWindowsUserStatePin(path string) (*os.File, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES|windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: open %s: %w", path, err)
	}
	return os.NewFile(uintptr(handle), path), nil
}

// WindowsACPUserCopy is an account profile that holds DefenseClaw's managed
// ACP state: <home>\.defenseclaw\acp with the user's token copies and the
// editor contract locks.
type WindowsACPUserCopy struct {
	SID  string
	Home string
}

// WindowsManagedACPUserCopies lists every local profile whose
// .defenseclaw\acp folder holds managed ACP state, signed in or not,
// revoked or ACP-only: a plain folder its account does not own (the
// enrollment created it for the gateway service), or one the account's own
// `enterprise acp setup` run created, which holds the managed token copy
// (<client>-<agent>.token) or contract locks without a per-user install's
// .token. Owner alone missed every account whose setup command made the
// folder, so the purge left their token copies and locks (GAP-0773). A
// per-user install's folder is not listed. A purge removes these copies:
// once the gateway is gone nothing accepts the tokens.
func WindowsManagedACPUserCopies() ([]WindowsACPUserCopy, error) {
	names, err := windowsProfileListSubkeyReader()
	if err != nil {
		return nil, err
	}
	var copies []WindowsACPUserCopy
	for _, sidText := range names {
		sid, err := windows.StringToSid(sidText)
		if err != nil {
			continue
		}
		home, err := windowsProfileImagePathReader(sidText)
		if err != nil {
			continue
		}
		acpDir := filepath.Join(home, ".defenseclaw", "acp")
		info, err := os.Lstat(acpDir)
		if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			continue
		}
		owner, err := windowsPathOwnerNoFollow(acpDir)
		if err != nil {
			continue
		}
		if owner.Equals(sid) && !windowsACPFolderHoldsManagedState(acpDir) {
			continue
		}
		copies = append(copies, WindowsACPUserCopy{SID: sidText, Home: home})
	}
	return copies, nil
}

// windowsACPFolderHoldsManagedState reports a .defenseclaw\acp folder with
// the files `enterprise acp setup` writes: a managed token copy
// (<client>-<agent>.token), or contract locks without the .token a
// per-user install writes.
func windowsACPFolderHoldsManagedState(acpDir string) bool {
	entries, err := os.ReadDir(acpDir)
	if err != nil {
		return false
	}
	perUserToken, locks := false, false
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		switch {
		case name == ".token":
			perUserToken = true
		case strings.HasSuffix(name, ".contract-lock.json"):
			locks = true
		case strings.HasSuffix(name, ".token") && strings.Contains(strings.TrimSuffix(name, ".token"), "-"):
			return true
		}
	}
	return locks && !perUserToken
}

// PurgeWindowsACPUserState removes the account's DefenseClaw ACP folder
// (<home>\.defenseclaw\acp) as LocalSystem, whether or not the account is
// signed in, and then its .defenseclaw folder once that is empty. The rest
// of the folder is left as found.
func PurgeWindowsACPUserState(rawHome, rawSID string) error {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	home, sid, err := validateWindowsEnterpriseHome(rawHome, rawSID)
	if err != nil {
		return err
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := purgeWindowsUserStateFolder(home, sid, filepath.Join(dataDir, "acp")); err != nil {
		return err
	}
	_ = os.Remove(dataDir)
	return nil
}
