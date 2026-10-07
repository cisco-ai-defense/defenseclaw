// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	// windowsPowerShell7RegistryKey is where the PowerShell 7 MSI registers
	// each installed engine (one subkey per upgrade code). HKLM\SOFTWARE is
	// administrator-writable only.
	windowsPowerShell7RegistryKey = `SOFTWARE\Microsoft\PowerShellCore\InstalledVersions`
	// windowsPowerShell7Publisher is the Authenticode signer of pwsh.exe.
	windowsPowerShell7Publisher = "Microsoft Corporation"

	windowsCMSGSignerInfoParam = 6 // CMSG_SIGNER_INFO_PARAM
)

var (
	windowsEnterprisePowerShell7Finder = findWindowsPowerShell7

	modCrypt32               = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam     = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose        = modCrypt32.NewProc("CryptMsgClose")
	errPowerShell7Required   = errors.New("powershell7_required")
	errPowerShell7Untrusted  = errors.New("powershell7_untrusted")
	windowsPowerShell7Verify = verifyWindowsMicrosoftAuthenticode
)

// windowsImageFileMachineAMD64 is IMAGE_FILE_MACHINE_AMD64.
const windowsImageFileMachineAMD64 = 0x8664

// windowsEnterpriseNativeMachine reports the host's native machine type,
// which an x64 process emulated on Windows ARM64 cannot hide.
var windowsEnterpriseNativeMachine = func() (uint16, error) {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err != nil {
		return 0, err
	}
	return native, nil
}

// validateWindowsEnterpriseStandaloneHost refuses a standalone lifecycle
// on anything but a native x64 process on native Windows x64, before any
// engine is launched.
func validateWindowsEnterpriseStandaloneHost() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("unsupported_architecture: the standalone enterprise lifecycle requires the x64 DefenseClaw CLI (this is %s)", runtime.GOARCH)
	}
	native, err := windowsEnterpriseNativeMachine()
	if err != nil {
		return fmt.Errorf("unsupported_architecture: identify the native machine type: %w", err)
	}
	if native != windowsImageFileMachineAMD64 {
		return fmt.Errorf("unsupported_architecture: the standalone enterprise lifecycle requires native Windows x64 (native machine 0x%04x); x64 emulation on ARM64 is not certified", native)
	}
	return nil
}

// windowsPowerShell7 is a validated PowerShell 7 engine.
type windowsPowerShell7 struct {
	Executable string // ...\PowerShell\7\pwsh.exe
	Home       string // $PSHOME
	Version    string
}

// windowsCMSGSignerInfo is the prefix of CMSG_SIGNER_INFO the signer lookup
// needs (issuer and serial number).
type windowsCMSGSignerInfo struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

// findWindowsPowerShell7 resolves the newest stable PowerShell 7 engine from
// its protected HKLM registration, requires it under the trusted Program
// Files root with an administrator-only ancestor chain, and requires a
// valid Microsoft Authenticode signature on pwsh.exe. It never consults
// PATH, App Paths, or the caller's ProgramFiles variable.
func findWindowsPowerShell7() (windowsPowerShell7, error) {
	programFiles, err := windowsEnterpriseProgramFilesResolver()
	if err != nil {
		return windowsPowerShell7{}, fmt.Errorf("resolve the trusted Program Files directory: %w", err)
	}
	root, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		windowsPowerShell7RegistryKey,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return windowsPowerShell7{}, fmt.Errorf("%w: PowerShell 7 (x64 MSI) is not installed: %v", errPowerShell7Required, err)
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return windowsPowerShell7{}, fmt.Errorf("%w: enumerate PowerShell 7 registrations: %v", errPowerShell7Required, err)
	}
	var (
		best        windowsPowerShell7
		bestVersion []int
	)
	for _, name := range names {
		key, err := registry.OpenKey(root, name, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		version, _, versionErr := key.GetStringValue("SemanticVersion")
		location, _, locationErr := key.GetStringValue("InstallLocation")
		key.Close()
		if versionErr != nil || locationErr != nil {
			continue
		}
		parsed, ok := parseWindowsPowerShell7Version(version)
		if !ok {
			continue
		}
		home, ok := windowsPowerShell7Home(location, programFiles)
		if !ok {
			continue
		}
		if bestVersion == nil || compareWindowsVersions(parsed, bestVersion) > 0 {
			best = windowsPowerShell7{Executable: filepath.Join(home, "pwsh.exe"), Home: home, Version: version}
			bestVersion = parsed
		}
	}
	if bestVersion == nil {
		return windowsPowerShell7{}, fmt.Errorf("%w: no stable x64 PowerShell 7 is registered under %s", errPowerShell7Required, filepath.Join(programFiles, "PowerShell"))
	}
	info, err := os.Lstat(best.Executable)
	if err != nil {
		return windowsPowerShell7{}, fmt.Errorf("%w: %s: %v", errPowerShell7Required, best.Executable, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return windowsPowerShell7{}, fmt.Errorf("%w: %s is not a regular non-link file", errPowerShell7Untrusted, best.Executable)
	}
	if err := managed.ValidateTrustedFilePath(best.Executable, "PowerShell 7"); err != nil {
		return windowsPowerShell7{}, fmt.Errorf("%w: %v", errPowerShell7Untrusted, err)
	}
	if err := windowsPowerShell7Verify(best.Executable, windowsPowerShell7Publisher); err != nil {
		return windowsPowerShell7{}, fmt.Errorf("%w: %v", errPowerShell7Untrusted, err)
	}
	return best, nil
}

// parseWindowsPowerShell7Version accepts stable 7.x or later versions only;
// preview and release-candidate engines are not certified.
func parseWindowsPowerShell7Version(value string) ([]int, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "-+") {
		return nil, false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return nil, false
	}
	parsed := make([]int, 0, len(parts))
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return nil, false
		}
		parsed = append(parsed, number)
	}
	return parsed, parsed[0] >= 7
}

func compareWindowsVersions(left, right []int) int {
	for index := 0; index < len(left) || index < len(right); index++ {
		var a, b int
		if index < len(left) {
			a = left[index]
		}
		if index < len(right) {
			b = right[index]
		}
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	return 0
}

// windowsPowerShell7Home returns the clean install directory when it is a
// strict descendant of the trusted Program Files root.
func windowsPowerShell7Home(location, programFiles string) (string, bool) {
	location = strings.TrimSpace(location)
	if location == "" || strings.ContainsAny(location, "%\x00\r\n/") || !filepath.IsAbs(location) {
		return "", false
	}
	home := filepath.Clean(location)
	base := filepath.Clean(programFiles)
	prefix := base + string(filepath.Separator)
	if len(home) <= len(prefix) || !strings.EqualFold(home[:len(prefix)], prefix) {
		return "", false
	}
	return home, true
}

// verifyWindowsMicrosoftAuthenticode requires a valid embedded Authenticode
// signature whose signer certificate's simple display name is publisher.
func verifyWindowsMicrosoftAuthenticode(path, publisher string) error {
	signer, _, err := verifyWindowsAuthenticode(path)
	if err != nil {
		return err
	}
	if signer != publisher {
		return fmt.Errorf("%s is signed by %q, not %q", path, signer, publisher)
	}
	return nil
}

// verifyWindowsAuthenticode requires a valid embedded Authenticode signature
// and returns its signer certificate's simple display name and DER encoding.
// Revocation is not fetched so an offline MDM install works; the chain
// must still build to a locally trusted root.
func verifyWindowsAuthenticode(path string) (string, []byte, error) {
	pathPointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return "", nil, fmt.Errorf("encode Authenticode path: %w", err)
	}
	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: pathPointer,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL |
			windows.WTD_REVOCATION_CHECK_NONE |
			windows.WTD_DISABLE_MD2_MD4,
		UIContext: windows.WTD_UICONTEXT_EXECUTE,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return "", nil, fmt.Errorf("WinVerifyTrust rejected %s: %w", path, verifyErr)
	}
	if closeErr != nil {
		return "", nil, fmt.Errorf("close WinVerifyTrust state: %w", closeErr)
	}
	return windowsAuthenticodeSigner(pathPointer)
}

func windowsAuthenticodeSigner(path *uint16) (string, []byte, error) {
	var (
		encoding, contentType, formatType uint32
		store, message                    windows.Handle
	)
	if err := windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(path),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&encoding,
		&contentType,
		&formatType,
		&store,
		&message,
		nil,
	); err != nil {
		return "", nil, fmt.Errorf("read the embedded Authenticode signature: %w", err)
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(message))

	var size uint32
	if ok, _, err := procCryptMsgGetParam.Call(uintptr(message), windowsCMSGSignerInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); ok == 0 {
		return "", nil, fmt.Errorf("size the Authenticode signer: %w", windowsLastError(err))
	}
	if size < uint32(unsafe.Sizeof(windowsCMSGSignerInfo{})) || size > 1<<20 {
		return "", nil, errors.New("the Authenticode signer information has an invalid size")
	}
	buffer := make([]byte, size)
	if ok, _, err := procCryptMsgGetParam.Call(uintptr(message), windowsCMSGSignerInfoParam, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size))); ok == 0 {
		return "", nil, fmt.Errorf("read the Authenticode signer: %w", windowsLastError(err))
	}
	signerInfo := (*windowsCMSGSignerInfo)(unsafe.Pointer(&buffer[0]))
	certInfo := windows.CertInfo{Issuer: signerInfo.Issuer, SerialNumber: signerInfo.SerialNumber}
	certificate, err := windows.CertFindCertificateInStore(
		store,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_SUBJECT_CERT,
		unsafe.Pointer(&certInfo),
		nil,
	)
	if err != nil {
		return "", nil, fmt.Errorf("find the Authenticode signer certificate: %w", err)
	}
	defer windows.CertFreeCertificateContext(certificate)
	chars := windows.CertGetNameString(certificate, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
	if chars <= 1 || chars > 1024 {
		return "", nil, errors.New("the Authenticode signer certificate has no display name")
	}
	name := make([]uint16, chars)
	windows.CertGetNameString(certificate, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name[0], chars)
	if certificate.EncodedCert == nil || certificate.Length == 0 {
		return "", nil, errors.New("the Authenticode signer certificate is empty")
	}
	encoded := append([]byte(nil), unsafe.Slice(certificate.EncodedCert, certificate.Length)...)
	return windows.UTF16ToString(name), encoded, nil
}

func windowsLastError(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) && errno != 0 {
		return errno
	}
	return errors.New("unknown error")
}

// trustedWindowsEnterprisePowerShell7Environment is the Windows PowerShell
// allowlist with the module path and PATH pointed at the validated PowerShell
// 7 engine instead of Windows PowerShell.
func trustedWindowsEnterprisePowerShell7Environment(powerShellTemp string, engine windowsPowerShell7) ([]string, error) {
	base, err := trustedWindowsEnterpriseEnvironment(powerShellTemp)
	if err != nil {
		return nil, err
	}
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return nil, fmt.Errorf("resolve the trusted Windows directory: %w", err)
	}
	system32 := filepath.Join(windowsDirectory, "System32")
	environment := make([]string, 0, len(base)+1)
	for _, entry := range base {
		key := entry
		if index := strings.IndexByte(entry, '='); index > 0 {
			key = entry[:index]
		}
		switch strings.ToUpper(key) {
		case "PSMODULEPATH", "PATH":
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(environment,
		"PSModulePath="+filepath.Join(engine.Home, "Modules"),
		"PATH="+strings.Join([]string{
			system32,
			windowsDirectory,
			filepath.Join(system32, "Wbem"),
			engine.Home,
		}, string(os.PathListSeparator)),
		// Telemetry and update checks would otherwise reach the network
		// from an elevated lifecycle.
		"POWERSHELL_TELEMETRY_OPTOUT=1",
		"POWERSHELL_UPDATECHECK=Off",
	)
	return environment, nil
}
