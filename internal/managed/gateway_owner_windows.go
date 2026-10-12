//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsTokenOwnerSetter is the token half of
// AdoptWindowsGatewayServiceFileOwner; tests substitute it.
type windowsTokenOwnerSetter interface {
	windowsTokenIdentity
	setDefaultOwner(owner *windows.SID) error
	defaultOwner() (*windows.SID, error)
}

// windowsTokenOwnerInfo mirrors TOKEN_OWNER.
type windowsTokenOwnerInfo struct{ Owner *windows.SID }

type windowsProcessTokenOwner struct{ token windows.Token }

func (t windowsProcessTokenOwner) GetTokenUser() (*windows.Tokenuser, error) {
	return t.token.GetTokenUser()
}

func (t windowsProcessTokenOwner) GetTokenGroups() (*windows.Tokengroups, error) {
	return t.token.GetTokenGroups()
}

func (t windowsProcessTokenOwner) setDefaultOwner(owner *windows.SID) error {
	value := windowsTokenOwnerInfo{Owner: owner}
	return windows.SetTokenInformation(
		t.token,
		windows.TokenOwner,
		(*byte)(unsafe.Pointer(&value)),
		uint32(unsafe.Sizeof(value)),
	)
}

func (t windowsProcessTokenOwner) defaultOwner() (*windows.SID, error) {
	var size uint32
	_ = windows.GetTokenInformation(t.token, windows.TokenOwner, nil, 0, &size)
	if size < uint32(unsafe.Sizeof(windowsTokenOwnerInfo{})) {
		return nil, errors.New("token owner is unavailable")
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(t.token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		return nil, err
	}
	owner := (*windowsTokenOwnerInfo)(unsafe.Pointer(&buffer[0])).Owner
	if owner == nil {
		return nil, errors.New("token owner is unavailable")
	}
	return owner.Copy()
}

var openWindowsProcessTokenOwner = func() (windowsTokenOwnerSetter, func(), error) {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT,
		&token,
	); err != nil {
		return nil, nil, err
	}
	return windowsProcessTokenOwner{token: token}, func() { _ = token.Close() }, nil
}

// windowsPinnedGatewayServiceSID resolves the gateway service SID pinned in
// the service environment, or nil when no pin is set.
func windowsPinnedGatewayServiceSID() (*windows.SID, error) {
	account := strings.TrimSpace(os.Getenv(WindowsServiceAccountEnv))
	if account == "" {
		return nil, nil
	}
	return windowsVirtualServiceSID(account)
}

// AdoptWindowsGatewayServiceFileOwner makes the managed gateway's service SID
// the default owner of the files and objects the gateway creates.
//
// The gateway logs on as LocalSystem with a restricted service SID, so its
// token is write-restricted: a write such as WRITE_DAC passes only when the
// DACL, or an owner's implicit rights, also grant it to one of the
// restricting SIDs (the service SID, Everyone, the logon SID, WRITE
// RESTRICTED). A LocalSystem token's default owner is SYSTEM, which is not
// one of them, so the gateway could not apply the protected DACL to its own
// new audit database, its SQLite sidecars, judge bodies or JSONL logs
// ("reopen existing database file for ACL hardening: Access is denied") and
// the service never reached Running. Under 1.0.0's virtual account those
// files were owned by the service SID. SCM grants the service SID
// SE_GROUP_OWNER in the gateway token, so the gateway sets it as the
// token's default owner and its files keep the 1.0.0 ownership. That
// restores the earlier owner rights only; it grants nothing new.
//
// Every process that is not the managed gateway service running as
// LocalSystem is unchanged. The gateway fails closed when it cannot adopt
// and verify the owner.
func AdoptWindowsGatewayServiceFileOwner() error {
	serviceSID, err := windowsPinnedGatewayServiceSID()
	if err != nil || serviceSID == nil {
		// No pin, or a pin that cannot name a service: not the managed
		// gateway. Later managed-path checks report a bad pin themselves.
		return nil
	}
	token, closeToken, err := openWindowsProcessTokenOwner()
	if err != nil {
		isGateway, identityErr := windowsTokenRunsAsService(windowsCurrentProcessToken{}, serviceSID)
		if identityErr == nil && !isGateway {
			return nil
		}
		return fmt.Errorf("managed gateway open its process token to set the file owner: %w", err)
	}
	defer closeToken()
	return adoptWindowsGatewayServiceFileOwner(token, serviceSID)
}

func adoptWindowsGatewayServiceFileOwner(token windowsTokenOwnerSetter, serviceSID *windows.SID) error {
	isGateway, err := windowsTokenRunsAsService(token, serviceSID)
	if err != nil {
		return fmt.Errorf("managed gateway verify its service identity: %w", err)
	}
	if !isGateway {
		return nil
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("managed gateway read its token user: %w", err)
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		// The 1.0.0 virtual-account logon already owns its files as the
		// service SID.
		return nil
	}
	if err := token.setDefaultOwner(serviceSID); err != nil {
		return fmt.Errorf("managed gateway set its service SID as the file owner: %w", err)
	}
	owner, err := token.defaultOwner()
	if err != nil {
		return fmt.Errorf("managed gateway verify its file owner: %w", err)
	}
	if !owner.Equals(serviceSID) {
		return fmt.Errorf("managed gateway file owner is %s, want service SID %s", owner, serviceSID)
	}
	return nil
}

// windowsCurrentProcessToken reads the current process token through its
// pseudo-handle (query access only).
type windowsCurrentProcessToken struct{}

func (windowsCurrentProcessToken) GetTokenUser() (*windows.Tokenuser, error) {
	return windows.GetCurrentProcessToken().GetTokenUser()
}

func (windowsCurrentProcessToken) GetTokenGroups() (*windows.Tokengroups, error) {
	return windows.GetCurrentProcessToken().GetTokenGroups()
}

var windowsCurrentProcessIdentityToken windowsTokenIdentity = windowsCurrentProcessToken{}

// WindowsCurrentProcessOwnerSID returns the SID that owns what this process
// creates and that private-file checks treat as this process: the gateway
// service SID for the managed gateway service (as the 1.0.0 virtual account,
// or as LocalSystem after AdoptWindowsGatewayServiceFileOwner), and the
// token user for every other process.
func WindowsCurrentProcessOwnerSID() (*windows.SID, error) {
	user, err := windowsCurrentProcessIdentityToken.GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user == nil || user.User.Sid == nil {
		return nil, errors.New("current token user is unavailable")
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return user.User.Sid, nil
	}
	serviceSID, err := windowsPinnedGatewayServiceSID()
	if err != nil || serviceSID == nil {
		return user.User.Sid, nil
	}
	isGateway, err := windowsTokenRunsAsService(windowsCurrentProcessIdentityToken, serviceSID)
	if err != nil {
		return nil, err
	}
	if isGateway {
		return serviceSID, nil
	}
	return user.User.Sid, nil
}

// WindowsCurrentProcessRunsAsService reports whether the current process is
// the service whose service SID is serviceSID, as its virtual account or as
// LocalSystem carrying that SID.
func WindowsCurrentProcessRunsAsService(serviceSID *windows.SID) (bool, error) {
	return windowsTokenRunsAsService(windowsCurrentProcessIdentityToken, serviceSID)
}
