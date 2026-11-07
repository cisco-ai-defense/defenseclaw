//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	enterpriseHookWindowsOpenCodePortsLoad         = enterprisehooks.LoadWindowsOpenCodeServicePortsFull
	enterpriseHookWindowsOpenCodePortsWrite        = enterprisehooks.WriteWindowsOpenCodeServicePortsFull
	enterpriseHookWindowsOpenCodePortsLock         = enterprisehooks.LockWindowsOpenCodeServicePorts
	enterpriseHookWindowsOpenCodeRead              = enterprisepolicy.ReadOpenCodeServicePortAsUser
	enterpriseHookWindowsOpenCodeSet               = enterprisepolicy.SetOpenCodeServicePort
	enterpriseHookWindowsOpenCodeRunAs             = enterprisehooks.RunAsTargetWithS4U
	enterpriseHookWindowsOpenCodeClaims            = windowsOpenCodeClaims
	enterpriseHookWindowsOpenCodeClaim             = windowsClaimOpenCodePort
	enterpriseHookWindowsOpenCodeWarningWrite      = writeWindowsOpenCodePortWarnings
	enterpriseHookWindowsOpenCodeWarningItemsWrite = writeWindowsOpenCodePortWarningItems
	enterpriseHookWindowsOpenCodeReadTimeout       = 20 * time.Second
)

// Windows can leave a profile read pending after its timeout. Keep at most
// one such read for each SID, so an unavailable profile cannot occupy a
// process-wide pool and prevent other accounts from being read.
var enterpriseHookWindowsOpenCodeReads = struct {
	sync.Mutex
	pending map[string]bool
}{pending: map[string]bool{}}

func readWindowsOpenCodePortAsAccount(ctx context.Context, profile enterprisehooks.TargetCredentials) (int, error) {
	enterpriseHookWindowsOpenCodeReads.Lock()
	if enterpriseHookWindowsOpenCodeReads.pending[profile.SID] {
		enterpriseHookWindowsOpenCodeReads.Unlock()
		return 0, fmt.Errorf("account read is still pending")
	}
	enterpriseHookWindowsOpenCodeReads.pending[profile.SID] = true
	enterpriseHookWindowsOpenCodeReads.Unlock()
	type outcome struct {
		port int
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		var port int
		err := enterpriseHookWindowsOpenCodeRunAs(profile, func() (readErr error) {
			port, readErr = enterpriseHookWindowsOpenCodeRead(profile.UserHome)
			return readErr
		})
		enterpriseHookWindowsOpenCodeReads.Lock()
		delete(enterpriseHookWindowsOpenCodeReads.pending, profile.SID)
		enterpriseHookWindowsOpenCodeReads.Unlock()
		done <- outcome{port: port, err: err}
	}()
	timer := time.NewTimer(enterpriseHookWindowsOpenCodeReadTimeout)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.port, result.err
	case <-timer.C:
		return 0, fmt.Errorf("account read timed out")
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// enterpriseHookStandaloneOpenCodePorts gives each eligible Windows account
// a stable port. The protected record owns the binding; an account file is
// read once for an unrecorded SID and written as that account on every pass.
func enterpriseHookStandaloneOpenCodePorts(ctx context.Context, manifest enterprisehooks.Manifest) (map[string]int, error) {
	_, connectors, standalone, err := enterpriseHookWindowsGuardianOptions()
	if err != nil || !standalone {
		return nil, err
	}
	governed := false
	for _, name := range connectors {
		if strings.EqualFold(name, enterprisepolicy.ConnectorOpenCode) {
			governed = true
			break
		}
	}
	if !governed {
		return nil, nil
	}
	path := enterprisehooks.WindowsOpenCodeServicePortsPath(enterpriseHookManifest)
	unlock, err := enterpriseHookWindowsOpenCodePortsLock(path)
	if err != nil {
		return nil, fmt.Errorf("OpenCode service ports reconcile lock: %w", err)
	}
	defer unlock()
	profiles, err := enterpriseHookWindowsEligibleProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("OpenCode service ports: eligible profiles: %w", err)
	}
	if cfg != nil && (strings.EqualFold(strings.TrimSpace(cfg.Enterprise.Enrollment.Mode), config.EnterpriseEnrollmentManifest) ||
		cfg.Enterprise.Enrollment.UnenrolledUsers == config.EnterpriseUnenrolledDeny) {
		enrolled := map[string]bool{}
		for _, target := range manifest.Targets {
			if target.IsEnabled() && strings.EqualFold(target.Connector, enterprisepolicy.ConnectorOpenCode) {
				enrolled[strings.ToUpper(strings.TrimSpace(target.SID))] = true
			}
		}
		filtered := profiles[:0:0]
		for _, profile := range profiles {
			if enrolled[strings.ToUpper(strings.TrimSpace(profile.SID))] {
				filtered = append(filtered, profile)
			}
		}
		profiles = filtered
	}
	state, err := enterpriseHookWindowsOpenCodePortsLoad(path)
	if err != nil {
		_ = enterpriseHookWindowsOpenCodeWarningItemsWrite([]windowsOpenCodePortWarning{{Code: "opencode_port_record_unreadable", Message: fmt.Sprintf("OpenCode service ports record %s cannot be read (%v); repair the SYSTEM-only record before assigning new ports", path, err)}})
		return nil, fmt.Errorf("OpenCode service ports record: %w; repair the SYSTEM-only record before assigning new ports", err)
	}
	recorded := state.Ports
	ids := map[string]uint64{}
	for raw, port := range recorded {
		sid, err := windows.StringToSid(raw)
		if err != nil || sid.SubAuthorityCount() == 0 {
			return nil, fmt.Errorf("OpenCode service ports: invalid recorded SID")
		}
		ids[sid.String()] = uint64(sid.SubAuthority(uint32(sid.SubAuthorityCount() - 1)))
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("OpenCode service ports: invalid recorded port")
		}
	}
	eligible := map[string]enterprisehooks.TargetCredentials{}
	imports := map[string]int{}
	unknown := map[string]bool{}
	var unknownEntries []enterprisehooks.WindowsOpenCodePortUnknown
	failedImports := map[int]string{}
	var problems error
	for _, profile := range profiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sid, err := windows.StringToSid(strings.TrimSpace(profile.SID))
		if err != nil || !enterprisehooks.WindowsInteractiveUserSID(profile.SID) || sid.SubAuthorityCount() == 0 {
			return nil, fmt.Errorf("OpenCode service ports: eligible profile has an invalid SID")
		}
		key := sid.String()
		ids[key] = uint64(sid.SubAuthority(uint32(sid.SubAuthorityCount() - 1)))
		profile.SID = key
		eligible[key] = profile
		if _, bound := recorded[key]; bound || state.ImportDone {
			continue
		}
		file := enterprisepolicy.OpenCodeServiceConfigPath(profile.UserHome)
		if strings.TrimSpace(profile.UserHome) == "" {
			unknown[key] = true
			unknownEntries = append(unknownEntries, enterprisehooks.WindowsOpenCodePortUnknown{SID: key, Path: file, Reason: "home is unavailable", Fix: "repair the account profile"})
			problems = errors.Join(problems, fmt.Errorf("OpenCode service port for %s: home is unavailable; check that account's profile before managing %s", key, file))
			continue
		}
		port, err := readWindowsOpenCodePortAsAccount(ctx, profile)
		if err != nil {
			unknown[key] = true
			unknownEntries = append(unknownEntries, enterprisehooks.WindowsOpenCodePortUnknown{SID: key, Path: file, Reason: err.Error(), Fix: "repair the account file or profile"})
			problems = errors.Join(problems, fmt.Errorf("OpenCode service port for %s: cannot read %s as that account: %w; repair the account file or profile", key, file, err))
			continue
		}
		if port > 0 {
			imports[key] = port
		}
	}
	claims, err := enterpriseHookWindowsOpenCodeClaims()
	if err != nil {
		return nil, errors.Join(problems, fmt.Errorf("OpenCode service port claims: %w", err))
	}
	keys := make([]string, 0, len(eligible))
	for key := range eligible {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	marks := map[int]bool{}
	for _, mark := range state.Contested {
		marks[mark.Port] = true
	}
	plan := enterprisepolicy.PlanOpenCodeServicePortsByAccountWithClaims(ids, keys, imports, recorded, claims, true, unknown, !state.ImportDone, marks)
	for _, conflict := range plan.Conflicts {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise hooks: OpenCode service port %d for %s is held by %s; %s gets port %d\n",
			conflict.Port, conflict.Account, conflict.Holder, conflict.Account, plan.Ports[conflict.Account])
	}
	contested := make([]int, 0, len(plan.Contested))
	for port := range plan.Contested {
		contested = append(contested, port)
	}
	sort.Ints(contested)
	for _, port := range contested {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise hooks: OpenCode service port %d is named by several unrecorded accounts, so it is given to none: %s; clear the mark with %s\n", port, strings.Join(plan.Contested[port], ", "), windowsOpenCodePortClearCommand(port))
		state.Contested = append(state.Contested, enterprisehooks.WindowsOpenCodeContestedPort{Port: port, SIDs: plan.Contested[port]})
	}
	for _, key := range plan.NoPort {
		problems = errors.Join(problems, fmt.Errorf("OpenCode service ports: no port is available for %s", key))
	}
	resultRecord := plan.Record
	// Resolve claim failures before publishing the complete protected record.
	// A failed claim cannot become a binding in this pass.
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(problems, err)
		}
		port := plan.Ports[key]
		if port == 0 || unknown[key] || recorded[key] != 0 {
			continue
		}
		if err := enterpriseHookWindowsOpenCodeClaim(key, port); err != nil {
			delete(resultRecord, key)
			if !state.ImportDone {
				if imported := imports[key]; imported > 0 && imported != enterprisepolicy.OpenCodeDefaultServicePort && imported != 49375 {
					failedImports[imported] = key
				}
			}
			problems = errors.Join(problems, fmt.Errorf("OpenCode service port claim for %s: %w", key, err))
		}
	}
	// An imported port still named by a file after a failed claim remains
	// reserved when the import window closes.
	for port, sid := range failedImports {
		held := false
		for _, mark := range state.Contested {
			if mark.Port == port {
				held = true
				break
			}
		}
		for _, bound := range resultRecord {
			if bound == port {
				held = true
				break
			}
		}
		if !held {
			state.Contested = append(state.Contested, enterprisehooks.WindowsOpenCodeContestedPort{Port: port, SIDs: []string{sid}})
		}
	}
	state.Ports, state.Unknown, state.ImportDone = resultRecord, unknownEntries, true
	if err := enterpriseHookWindowsOpenCodePortsWrite(path, state); err != nil {
		_ = enterpriseHookWindowsOpenCodeWarningItemsWrite([]windowsOpenCodePortWarning{{Code: "opencode_port_record_unreadable", Message: fmt.Sprintf("OpenCode service ports record %s could not be written (%v); repair the SYSTEM-only record", path, err)}})
		return nil, errors.Join(problems, fmt.Errorf("OpenCode service ports record: %w; no account file was rewritten", err))
	}
	// The committed record decides every account-side rewrite. A refused file
	// keeps its binding, and the next guardian pass tries that file again.
	available := map[string]int{}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return available, errors.Join(problems, err)
		}
		port := resultRecord[key]
		if port == 0 || unknown[key] {
			continue
		}
		profile := eligible[key]
		err := enterpriseHookWindowsOpenCodeRunAs(profile, func() error {
			result, err := enterpriseHookWindowsOpenCodeSet(profile.UserHome, port)
			if err != nil {
				return err
			}
			if result.Port != port {
				return fmt.Errorf("account port %d differs from recorded port %d", result.Port, port)
			}
			return nil
		})
		if err != nil {
			file := enterprisepolicy.OpenCodeServiceConfigPath(profile.UserHome)
			unknownEntries = append(unknownEntries, enterprisehooks.WindowsOpenCodePortUnknown{SID: key, Path: file, Reason: err.Error(), Fix: "repair the account file or profile"})
			problems = errors.Join(problems, fmt.Errorf("OpenCode service port for %s: cannot write %s as that account: %w; repair the account file or profile", key, file, err))
			continue
		}
		available[key] = port
	}
	if len(unknownEntries) != len(state.Unknown) {
		state.Unknown = unknownEntries
		if err := enterpriseHookWindowsOpenCodePortsWrite(path, state); err != nil {
			problems = errors.Join(problems, fmt.Errorf("OpenCode service port warnings record: %w", err))
		}
	}
	if err := enterpriseHookWindowsOpenCodeWarningWrite(state); err != nil {
		return available, errors.Join(problems, fmt.Errorf("OpenCode port warning summary: %w", err))
	}
	return available, problems
}

// windowsOpenCodeClaimPath mirrors the per-user setup claim namespace.
func windowsOpenCodeClaimPath(port int) string {
	dir := strings.TrimSpace(os.Getenv("ProgramData"))
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, fmt.Sprintf("defenseclaw-opencode-port-%d", port))
}

func windowsOpenCodeClaims() (map[int]string, error) {
	dir := filepath.Dir(windowsOpenCodeClaimPath(enterprisepolicy.OpenCodeAccountPortBase))
	if err := winpath.RejectReparseChain(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	claims := map[int]string{}
	const prefix = "defenseclaw-opencode-port-"
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		port, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), prefix))
		if err != nil || port <= 0 || port > 65535 || entry.Name() != prefix+strconv.Itoa(port) {
			continue
		}
		owner := windowsOpenCodeClaimOwner(filepath.Join(dir, entry.Name()))
		if owner == "" {
			owner = "!"
		}
		claims[port] = owner
	}
	return claims, nil
}

func windowsOpenCodeClaimOwner(path string) string {
	if err := winpath.RejectReparseChain(filepath.Dir(path)); err != nil {
		return ""
	}
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return ""
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return ""
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(data) > 256 {
		return ""
	}
	sid, err := windows.StringToSid(strings.TrimSpace(string(data)))
	if err != nil || !enterprisehooks.WindowsInteractiveUserSID(sid.String()) {
		return ""
	}
	return sid.String()
}

func windowsClaimOpenCodePort(sid string, port int) error {
	path := windowsOpenCodeClaimPath(port)
	if err := winpath.RejectReparseChain(filepath.Dir(path)); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if errors.Is(err, os.ErrExist) {
		if windowsOpenCodeClaimOwner(path) == sid {
			return nil
		}
		return fmt.Errorf("port %d is already claimed by another account", port)
	}
	if err != nil {
		return err
	}
	if _, err := file.WriteString(sid); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
