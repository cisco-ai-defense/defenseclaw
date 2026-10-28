// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory/ideplugins"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// windowsIDEAppDataRescan is how long a published record is kept before the
// account's IDEs are read again; windowsIDEAppDataBudget bounds the reads of
// one cycle, the oldest records first (scanIDEAppDataDue); the rest keep
// their records until a later cycle.
const (
	windowsIDEAppDataRescan = 5 * time.Minute
	windowsIDEAppDataBudget = 20 * time.Second
)

const windowsUserShellFoldersKey = `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

// windowsIDEAppDataNoted holds the refusals already logged, so each is
// logged once per enumerator process.
var windowsIDEAppDataNoted sync.Map

// WriteWindowsIDEAppDataSpool publishes, for every profile the manifest
// grants inventory read access to whose roaming or local AppData folder
// redirection moved, the IDE inventory of that profile read as LocalSystem
// (IDEAppDataSpoolDirName). The redirected folders come from the account's
// User Shell Folders while its registry is loaded, and from its last record
// otherwise. A folder is read only when it is a local folder the account
// owns, reached without a link or junction, and it is held open through
// the scan (windowsScanIDEAppData); the scan does not follow links below it
// or below the profile. Records of other profiles are removed, so
// the gateway scans those itself.
func WriteWindowsIDEAppDataSpool(dir string, manifest Manifest, setOwnership func(string) error, logf func(string, ...any)) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create ide appdata spool: %w", err)
	}
	if setOwnership != nil {
		if err := setOwnership(dir); err != nil {
			return fmt.Errorf("set ide appdata spool protection: %w", err)
		}
	}
	keep := map[string]bool{}
	deadline := time.Now().Add(windowsIDEAppDataBudget)
	var due []ideAppDataDue
	records := map[string]IDEAppDataSpoolRecord{}
	for _, target := range inventoryDACLGrantTargets(manifest) {
		key := strings.ToUpper(strings.TrimSpace(target.SID))
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		if !strings.HasPrefix(key, "S-1-") || !validIdentitySpoolKey(key) || !filepath.IsAbs(home) {
			continue
		}
		name := key + ".json"
		previous, err := ReadIDEAppDataSpool(dir, key, nil)
		havePrevious := err == nil && strings.EqualFold(filepath.Clean(previous.Home), home)
		roaming, local, known := windowsRedirectedAppData(key, home, target.User, logf)
		if !known {
			if !havePrevious {
				continue
			}
			roaming, local = previous.RoamingAppData, previous.LocalAppData
		}
		roaming = windowsUsableIDEAppDataFolder(key, roaming, logf)
		local = windowsUsableIDEAppDataFolder(key, local, logf)
		if roaming == "" && local == "" {
			continue
		}
		now := time.Now()
		sameFolders := havePrevious && strings.EqualFold(previous.RoamingAppData, roaming) && strings.EqualFold(previous.LocalAppData, local)
		if sameFolders && !previous.UpdatedAt.After(now) && now.Sub(previous.UpdatedAt) < windowsIDEAppDataRescan {
			keep[strings.ToLower(name)] = true
			continue
		}
		item := ideAppDataDue{name: name}
		if sameFolders {
			item.published = previous.UpdatedAt
		}
		due = append(due, item)
		records[name] = IDEAppDataSpoolRecord{
			Version: IDEAppDataSpoolRecordVersion, Key: key, Home: home,
			RoamingAppData: roaming, LocalAppData: local,
		}
	}
	scanned := scanIDEAppDataDue(due, func() bool { return time.Now().After(deadline) }, func(item ideAppDataDue) bool {
		record, ok := windowsScanIDEAppData(records[item.name], logf)
		if !ok {
			return false
		}
		data, err := json.Marshal(record)
		if err == nil && len(data) > maxIDEAppDataSpoolRecordBytes {
			err = fmt.Errorf("the IDE inventory exceeds %d bytes", maxIDEAppDataSpoolRecordBytes)
		}
		if err == nil {
			err = writeSpoolBytes(dir, item.name, ".ide-appdata-*", data, setOwnership)
		}
		if err != nil && logf != nil {
			logf("[hook-enumerator] WARN publish the IDE inventory of redirected AppData for %s: %v", record.Key, err)
		}
		return err == nil
	})
	for name, kept := range scanned {
		keep[strings.ToLower(name)] = kept
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if !keep[strings.ToLower(entry.Name())] {
				_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
			}
		}
	}
	return nil
}

// windowsRedirectedAppData reads the account's redirected roaming and local
// AppData folders from its User Shell Folders. known is false while its
// registry is not loaded (the account is signed out).
func windowsRedirectedAppData(sid, home, user string, logf func(string, ...any)) (roaming, local string, known bool) {
	key, err := registry.OpenKey(registry.USERS, sid+`\`+windowsUserShellFoldersKey, registry.QUERY_VALUE)
	if err != nil {
		return "", "", false
	}
	defer key.Close()
	folder := func(name, defaultRel string) string {
		raw, _, err := key.GetStringValue(name)
		if err != nil {
			return ""
		}
		folder, refused := RedirectedAppDataFolder(raw, home, user, defaultRel)
		if refused != "" {
			windowsNoteIDEAppData(logf, sid, name+" "+refused, raw)
		}
		return folder
	}
	return folder("AppData", `AppData\Roaming`), folder("Local AppData", `AppData\Local`), true
}

// beforeIDEAppDataScan, when set, runs between the hold on a record's
// folders and their scan; tests use it to swap a folder in that window.
var beforeIDEAppDataScan func(record IDEAppDataSpoolRecord)

// windowsScanIDEAppData reads the IDEs of record's redirected folders while
// it holds them (windowsHoldIDEAppDataFolder), and returns record with its
// installs; false when a folder cannot be held, or no longer names the held
// folder after the scan. The ownership check alone would go stale before the
// scan: an account that controls a folder above the redirected one could
// swap in an ordinary folder of its own between them, at the same path, and
// its plugins would be published as the profile owner's.
func windowsScanIDEAppData(record IDEAppDataSpoolRecord, logf func(string, ...any)) (IDEAppDataSpoolRecord, bool) {
	var holds []*windowsIDEAppDataHold
	defer func() {
		for _, hold := range holds {
			hold.close()
		}
	}()
	for _, folder := range []string{record.RoamingAppData, record.LocalAppData} {
		if folder == "" {
			continue
		}
		hold, err := windowsHoldIDEAppDataFolder(record.Key, folder)
		if err != nil {
			windowsNoteIDEAppData(logf, record.Key, "redirected AppData is not read: "+err.Error(), folder)
			return record, false
		}
		holds = append(holds, hold)
	}
	if beforeIDEAppDataScan != nil {
		beforeIDEAppDataScan(record)
	}
	record.UpdatedAt = time.Now().UTC()
	record.Installs = ideplugins.Scan(record.Home, "windows", ideplugins.Limits{RoamingAppData: record.RoamingAppData, LocalAppData: record.LocalAppData})
	for _, hold := range holds {
		if err := hold.stillNamed(record.Key); err != nil {
			windowsNoteIDEAppData(logf, record.Key, "redirected AppData is not read: "+err.Error(), hold.folder)
			return record, false
		}
	}
	return record, true
}

// windowsUsableIDEAppDataFolder returns folder when it can be read for the
// account sid (windowsHoldIDEAppDataFolder). Otherwise it returns "", and
// logs why once; a missing folder is skipped quietly.
func windowsUsableIDEAppDataFolder(sid, folder string, logf func(string, ...any)) string {
	if folder == "" {
		return ""
	}
	hold, err := windowsHoldIDEAppDataFolder(sid, folder)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return ""
	}
	if err != nil {
		windowsNoteIDEAppData(logf, sid, "redirected AppData is not read: "+err.Error(), folder)
		return ""
	}
	hold.close()
	return folder
}

// windowsIDEAppDataHold is a redirected AppData folder held open from its
// check to the end of its scan. The handle does not share delete, so the
// folder cannot be renamed or removed while it is held, and NTFS refuses to
// rename a folder above it while a handle below is open: the path the scan
// reads keeps naming the folder that was checked. stillNamed checks that
// after the scan.
type windowsIDEAppDataHold struct {
	handle windows.Handle
	folder string
	volume uint32
	index  uint64
}

// windowsHoldIDEAppDataFolder opens folder for the account sid when it is an
// existing local folder that sid owns, whose final path is folder itself, so
// no link or junction leads to it.
func windowsHoldIDEAppDataFolder(sid, folder string) (*windowsIDEAppDataHold, error) {
	ptr, err := winpath.UTF16Ptr(folder)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	hold := &windowsIDEAppDataHold{handle: handle, folder: folder}
	if err := hold.check(sid); err != nil {
		hold.close()
		return nil, err
	}
	return hold, nil
}

func (h *windowsIDEAppDataHold) check(sid string) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h.handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("it is not a folder")
	}
	h.volume, h.index = info.VolumeSerialNumber, uint64(info.FileIndexHigh)<<32|uint64(info.FileIndexLow)
	final, err := inventoryDACLFinalPath(h.handle)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimPrefix(final, `\\?\`), filepath.Clean(h.folder)) {
		return errors.New("a link or junction leads to it")
	}
	sd, err := windows.GetSecurityInfo(h.handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read its owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("it has no owner")
	}
	want, err := windows.StringToSid(sid)
	if err != nil {
		return err
	}
	if !windows.EqualSid(owner, want) {
		return errors.New("the account does not own it")
	}
	return nil
}

// stillNamed reports, after the scan, whether the path still opens to the
// held folder and sid still owns it.
func (h *windowsIDEAppDataHold) stillNamed(sid string) error {
	again, err := windowsHoldIDEAppDataFolder(sid, h.folder)
	if err != nil {
		return err
	}
	defer again.close()
	if again.volume != h.volume || again.index != h.index {
		return errors.New("another folder took its place during the scan")
	}
	return nil
}

func (h *windowsIDEAppDataHold) close() {
	if h != nil && h.handle != 0 {
		_ = windows.CloseHandle(h.handle)
		h.handle = 0
	}
}

func windowsNoteIDEAppData(logf func(string, ...any), sid, reason, value string) {
	if logf == nil {
		return
	}
	if _, seen := windowsIDEAppDataNoted.LoadOrStore(sid+"\x00"+reason+"\x00"+value, true); !seen {
		logf("[hook-enumerator] WARN IDE inventory for %s: %s", sid, reason)
	}
}
