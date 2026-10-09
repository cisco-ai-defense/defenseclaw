// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// RevokeGatewayInventoryReadForManifest removes the gateway service ACEs
// that GrantGatewayInventoryReadForManifest added to each enrolled account's
// inventory folders. The uninstall runs it before it removes the per-user
// registrations: some of those folders are also on a managed hook path
// (~\.config for Amp and OpenCode, ~\.gemini for Antigravity), and the
// removal trust check there expects the exact protected DACL, so the extra
// ACEs made it refuse to remove the registrations (GAP-1765). The service
// SIDs are derived from the names, so this works after the services are
// deleted. The IDE plugin inventory's folders and files, and every
// connector skill and plugin folder (GAP-0913), are revoked on every
// profile, whatever the profile granted. A missing path is skipped;
// per-path failures are returned.
func RevokeGatewayInventoryReadForManifest(manifest Manifest) error {
	names := []string{productionGatewayServiceName}
	if discovered, err := discoverGatewayServiceName(); err == nil && discovered != productionGatewayServiceName {
		names = append(names, discovered)
	}
	sids := make([]*windows.SID, 0, len(names))
	for _, name := range names {
		sid, err := windows.StringToSid(windowsServiceSIDString(name))
		if err != nil {
			return fmt.Errorf("enterprise hooks: gateway service SID for %s: %w", name, err)
		}
		sids = append(sids, sid)
	}
	dirs := append(append([]string(nil), inventoryDACLDotdirs...), inventoryDACLListOnlyDirs...)
	seen := map[string]struct{}{}
	var failures []error
	for _, target := range manifest.Targets {
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		if home == "." || home == "" {
			continue
		}
		key := strings.ToLower(home)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		homeDirs := append([]string(nil), dirs...)
		for _, ide := range inventoryDACLIDEGrants(home, nil) {
			homeDirs = append(homeDirs, ide.dir)
		}
		homeDirs = append(homeDirs, inventoryDACLComponentDirs(home)...)
		for _, dir := range homeDirs {
			if err := revokeInventoryACEs(filepath.Join(home, dir), sids); err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", filepath.Join(home, dir), err))
			}
		}
	}
	return errors.Join(failures...)
}

// revokeInventoryACEs removes every ACE for sids from the folder or regular
// file path's DACL and keeps the rest, including the DACL's protection.
func revokeInventoryACEs(path string, sids []*windows.SID) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !(info.IsDir() || info.Mode().IsRegular()) || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("get DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return nil
	}
	if !daclHasACEFor(dacl, sids) {
		return nil
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sid := range sids {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessMode: windows.REVOKE_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	revoked, err := windows.ACLFromEntries(entries, dacl)
	if err != nil {
		return fmt.Errorf("revoke ACE: %w", err)
	}
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control, _, err := sd.Control(); err == nil && control&windows.SE_DACL_PROTECTED != 0 {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, information, nil, nil, revoked, nil); err != nil {
		return fmt.Errorf("set DACL: %w", err)
	}
	return nil
}

func daclHasACEFor(dacl *windows.ACL, sids []*windows.SID) bool {
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, sid := range sids {
			if windows.EqualSid(aceSID, sid) {
				return true
			}
		}
	}
	return false
}

// inventoryDACLComponentDirs lists, relative to home, the skill and plugin
// folders of every connector, the folders inventoryDACLComponentGrants can
// grant. They are resolved below home itself (connector.WithUserHomeDir), so
// they do not depend on the token of the process that revokes: under Setup
// /uninstall the Known Folder Hermes resolves by left its bundled plugins
// folder out, and the gateway kept its read ACE there (GAP-0913).
func inventoryDACLComponentDirs(home string) []string {
	reg := connector.NewDefaultRegistry()
	var out []string
	_ = connector.WithUserHomeDir(home, func() error {
		for _, name := range reg.Names() {
			conn, ok := reg.Get(name)
			if !ok {
				continue
			}
			skills, plugins := connector.ComponentDirsForHome(conn, home, home)
			for _, dir := range append(skills, plugins...) {
				if rel, err := filepath.Rel(home, dir); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
					out = append(out, rel)
				}
			}
		}
		return nil
	})
	return out
}
