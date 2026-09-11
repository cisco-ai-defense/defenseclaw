// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package useridentity

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// profileListRegistryKey maps each local profile directory to the SID that
// owns it. It is the only mapping available to a service-context process,
// which cannot enumerate interactive sessions.
const profileListRegistryKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// currentIdentity reports the Windows token SID of the calling process.
//
// The thread token is consulted first so an impersonating hook reports the
// impersonated user rather than the process owner. That ordering is what makes
// the value usable as a per-user join key under the enterprise guardian, which
// repairs artifacts while impersonating a manifest-pinned SID.
func currentIdentity() Identity {
	sid := ""
	if fromThread, err := threadTokenSID(); err == nil {
		sid = fromThread
	}
	if sid == "" {
		if fromProcess, err := processTokenSID(); err == nil {
			sid = fromProcess
		}
	}
	if sid == "" {
		return Identity{}
	}
	return Identity{
		ID:     sid,
		IDKind: KindWindowsSID,
		Name:   accountNameForSID(sid),
	}
}

// identityForHome maps a profile directory back to its owning SID through
// ProfileList.
//
// The directory ACL owner is deliberately not used: a profile directory can
// be owned by Administrators after an in-place repair while still belonging to
// a user, and ProfileList is the same source the discovery scan used to find
// the directory in the first place, so the two agree by construction.
func identityForHome(home string) Identity {
	want := normalizeProfilePath(home)
	if want == "" {
		return Identity{}
	}
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListRegistryKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return Identity{}
	}
	defer root.Close()
	sids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return Identity{}
	}
	for _, sid := range sids {
		if KindForID(sid) != KindWindowsSID {
			continue
		}
		if normalizeProfilePath(profileImagePath(root, sid)) != want {
			continue
		}
		return Identity{
			ID:     sid,
			IDKind: KindWindowsSID,
			Name:   accountNameForSID(sid),
		}
	}
	return Identity{}
}

// homeForID reads the profile directory ProfileList records for a SID.
//
// A relative path is refused: a relative profile root would resolve against
// the gateway service's working directory and read files from somewhere that
// is not a user profile.
func homeForID(id string) string {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListRegistryKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer root.Close()
	home := strings.TrimSpace(profileImagePath(root, id))
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Clean(home)
}

// profileImagePath reads one ProfileList entry, expanding the environment
// references Windows stores in it (ProfileImagePath is REG_EXPAND_SZ and
// commonly holds %SystemDrive%\Users\name).
func profileImagePath(root registry.Key, sid string) string {
	key, err := registry.OpenKey(root, sid, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	raw, _, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return ""
	}
	expanded, err := registry.ExpandString(raw)
	if err != nil {
		return raw
	}
	return expanded
}

// normalizeProfilePath puts a path into a form two sources can be compared in.
// Windows paths are case-insensitive and the registry and the scanner disagree
// about trailing separators.
func normalizeProfilePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	cleaned := filepath.Clean(path)
	cleaned = strings.TrimRight(cleaned, `\/`)
	if cleaned == "" {
		return ""
	}
	return strings.ToLower(cleaned)
}

// accountNameForSID resolves the bare account name. The domain is dropped so
// the value cannot be mistaken for a qualified principal or an email, and an
// unresolvable SID yields an empty name rather than a synthesized one.
func accountNameForSID(sid string) string {
	parsed, err := windows.StringToSid(sid)
	if err != nil || parsed == nil {
		return ""
	}
	account, _, _, err := parsed.LookupAccount("")
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(account)
	if idx := strings.LastIndexAny(name, `\/`); idx >= 0 && idx+1 < len(name) {
		name = name[idx+1:]
	}
	return name
}

func threadTokenSID() (string, error) {
	var token windows.Token
	if err := windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY,
		true,
		&token,
	); err != nil {
		return "", err
	}
	defer token.Close()
	return tokenUserSID(token)
}

func processTokenSID() (string, error) {
	return tokenUserSID(windows.GetCurrentProcessToken())
}

func tokenUserSID(token windows.Token) (string, error) {
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return "", windows.ERROR_NONE_MAPPED
	}
	return tokenUser.User.Sid.String(), nil
}
