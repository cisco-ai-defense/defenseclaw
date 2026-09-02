// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package idfabric

import (
	"os/user"
	"strings"

	"golang.org/x/sys/windows"
)

// osIdentity reports the Windows token SID of the calling hook.
//
// The thread token is consulted first so an impersonating hook reports the
// impersonated user rather than the process owner; that ordering is what makes
// the value usable as a per-user join key under the enterprise guardian, which
// repairs artifacts while impersonating a manifest-pinned SID.
func osIdentity() User {
	if sid, err := threadTokenSID(); err == nil && sid != "" {
		return User{SID: sid}
	}
	if sid, err := processTokenSID(); err == nil && sid != "" {
		return User{SID: sid}
	}
	return User{}
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

// osUsername reports the OS account name for the device block. The bare
// account name is used rather than DOMAIN\user so it is not mistaken for a
// qualified principal or an email.
func osUsername() string {
	current, err := user.Current()
	if err != nil || current == nil {
		return ""
	}
	name := strings.TrimSpace(current.Username)
	if idx := strings.LastIndexAny(name, `\/`); idx >= 0 && idx+1 < len(name) {
		name = name[idx+1:]
	}
	return name
}
