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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	enterpriseHookWindowsOpenCodePortsLoad   = enterprisehooks.LoadWindowsOpenCodeServicePorts
	enterpriseHookWindowsOpenCodePortsWrite  = enterprisehooks.WriteWindowsOpenCodeServicePorts
	enterpriseHookWindowsOpenCodeRead        = enterprisepolicy.ReadOpenCodeServicePortAsUser
	enterpriseHookWindowsOpenCodeEnsure      = enterprisepolicy.EnsureOpenCodeServicePort
	enterpriseHookWindowsOpenCodeReplace     = enterprisepolicy.ReplaceOpenCodeServicePort
	enterpriseHookWindowsOpenCodeRunAs       = enterprisehooks.RunAsTargetWithS4U
	enterpriseHookWindowsOpenCodeClaims      = windowsOpenCodeClaims
	enterpriseHookWindowsOpenCodeClaim       = windowsClaimOpenCodePort
	enterpriseHookWindowsOpenCodeReadTimeout = 20 * time.Second
)

// A profile read can wait on an unavailable redirected home. Only a bounded
// number of timed-out readers may remain while Windows completes their I/O.
var enterpriseHookWindowsOpenCodeReadSlots = make(chan struct{}, 4)

func readWindowsOpenCodePortAsAccount(ctx context.Context, profile enterprisehooks.TargetCredentials) (int, error) {
	select {
	case enterpriseHookWindowsOpenCodeReadSlots <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
		return 0, fmt.Errorf("account reads are busy")
	}
	type outcome struct {
		port int
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() { <-enterpriseHookWindowsOpenCodeReadSlots }()
		var port int
		err := enterpriseHookWindowsOpenCodeRunAs(profile, func() (readErr error) {
			port, readErr = enterpriseHookWindowsOpenCodeRead(profile.UserHome)
			return readErr
		})
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

// enterpriseHookStandaloneOpenCodePorts gives every eligible Windows account
// a stable OpenCode service port while OpenCode is governed. The protected
// record retains a SID's reservation across changes to eligibility and
// account lookup. All service.json writes run as
// the account, including accounts whose coverage uses machine policy and
// has no per-user hook row to repair.
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
	path := enterprisehooks.WindowsOpenCodeServicePortsPath(enterpriseHookManifest)
	recorded, recordErr := enterpriseHookWindowsOpenCodePortsLoad(path)
	if recordErr != nil {
		return nil, fmt.Errorf("OpenCode service ports record: %w; new accounts wait until it is readable or reset", recordErr)
	}
	ids := map[string]uint64{}
	filePorts := map[string]int{}
	eligible := map[string]enterprisehooks.TargetCredentials{}
	for raw, port := range recorded {
		sid, err := windows.StringToSid(raw)
		if err != nil {
			return nil, fmt.Errorf("OpenCode service ports: invalid recorded SID")
		}
		key := sid.String()
		ids[key] = uint64(sid.SubAuthority(uint32(sid.SubAuthorityCount() - 1)))
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("OpenCode service ports: invalid recorded port")
		}
	}
	for _, profile := range profiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sid, err := windows.StringToSid(strings.TrimSpace(profile.SID))
		if err != nil || !enterprisehooks.WindowsInteractiveUserSID(profile.SID) {
			return nil, fmt.Errorf("OpenCode service ports: eligible profile has an invalid SID")
		}
		key := sid.String()
		ids[key] = uint64(sid.SubAuthority(uint32(sid.SubAuthorityCount() - 1)))
		profile.SID = key
		eligible[key] = profile
		if strings.TrimSpace(profile.UserHome) == "" {
			return nil, fmt.Errorf("OpenCode service port for %s is unknown: no home; no assignments changed", key)
		}
		port, err := readWindowsOpenCodePortAsAccount(ctx, profile)
		if err != nil {
			return nil, fmt.Errorf("OpenCode service port for %s is unknown: %w; no assignments changed", key, err)
		}
		if port > 0 {
			filePorts[key] = port
		}
	}
	claims, err := enterpriseHookWindowsOpenCodeClaims()
	if err != nil {
		return nil, fmt.Errorf("OpenCode service port claims: %w", err)
	}
	keys := make([]string, 0, len(eligible))
	for key := range eligible {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	plan := enterprisepolicy.PlanOpenCodeServicePortsByAccountWithClaims(ids, keys, filePorts, recorded, claims, true)
	resultRecord := plan.Record
	unavailable := map[string]bool{}
	// A failed account still has the port in its previous record or file.
	// Do not publish that port for a different SID in this pass, even when
	// that SID's claim is already present; the next pass will retry the move.
	keepPreviousRecord := func(key string) {
		unavailable[key] = true
		old := recorded[key]
		if old > 0 {
			resultRecord[key] = old
		} else {
			delete(resultRecord, key)
		}
		for _, held := range []int{old, filePorts[key]} {
			if held == 0 {
				continue
			}
			for other, assigned := range plan.Ports {
				if other != key && assigned == held {
					unavailable[other] = true
				}
			}
			if held == old {
				for other, port := range resultRecord {
					if other == key || port != old || recorded[other] == old {
						continue
					}
					if previous := recorded[other]; previous > 0 {
						resultRecord[other] = previous
					} else {
						delete(resultRecord, other)
					}
				}
			}
		}
	}
	var problems error
	for _, key := range plan.NoPort {
		keepPreviousRecord(key)
		problems = errors.Join(problems, fmt.Errorf("OpenCode service ports: no port is available for %s", key))
	}
	for _, conflict := range plan.Conflicts {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise hooks: OpenCode service port %d for %s is held by %s; assigned port %d\n",
			conflict.Port, conflict.Account, conflict.Holder, plan.Ports[conflict.Account])
	}
	claimed := map[string]bool{}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(problems, err)
		}
		if plan.Ports[key] == 0 {
			continue
		}
		if err := enterpriseHookWindowsOpenCodeClaim(key, plan.Ports[key]); err != nil {
			problems = errors.Join(problems, fmt.Errorf("OpenCode service port claim for %s: %w", key, err))
			keepPreviousRecord(key)
			continue
		}
		claimed[key] = true
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(problems, err)
		}
		if !claimed[key] {
			continue
		}
		port := plan.Ports[key]
		if filePorts[key] == port {
			continue
		}
		profile := eligible[key]
		err := enterpriseHookWindowsOpenCodeRunAs(profile, func() error {
			var result enterprisepolicy.OpenCodeServicePortResult
			var err error
			if stale := plan.Replace[key]; stale > 0 {
				result, err = enterpriseHookWindowsOpenCodeReplace(profile.UserHome, port, stale)
			} else {
				result, err = enterpriseHookWindowsOpenCodeEnsure(profile.UserHome, port)
			}
			if err != nil {
				return err
			}
			if result.Port != port {
				return fmt.Errorf("account port %d differs from assigned port %d", result.Port, port)
			}
			return nil
		})
		if err != nil {
			problems = errors.Join(problems, fmt.Errorf("OpenCode service port for %s: %w", key, err))
			keepPreviousRecord(key)
		}
	}
	if err := enterpriseHookWindowsOpenCodePortsWrite(path, resultRecord); err != nil {
		return nil, errors.Join(problems, fmt.Errorf("OpenCode service ports record: %w", err))
	}
	available := make(map[string]int, len(resultRecord))
	for key, port := range resultRecord {
		if !unavailable[key] {
			available[key] = port
		}
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
