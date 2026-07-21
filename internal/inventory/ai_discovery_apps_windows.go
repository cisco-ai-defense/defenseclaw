// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// The AppsFolder can expose both classic shortcuts and packaged apps. Keep
	// enumeration within the same global cap as the other application sources.
	maxWindowsShellApplications = maxWindowsApplicationNames
	maxWindowsShellDisplayUTF16 = 512
	maxWindowsShellParsingUTF16 = 1024

	windowsSIGDNNormalDisplay          = 0x00000000
	windowsSIGDNDesktopAbsoluteParsing = 0x80028000
	windowsHRESULTFalse                = 0x00000001
	windowsPackageIdentityPrefix       = "package-id:"
)

var (
	windowsIIDIShellItem = windows.GUID{
		Data1: 0x43826d1e, Data2: 0xe718, Data3: 0x42ee,
		Data4: [8]byte{0xbc, 0x55, 0xa1, 0xe2, 0x61, 0xc3, 0x7b, 0xfe},
	}
	windowsIIDIEnumShellItems = windows.GUID{
		Data1: 0x70629033, Data2: 0xe363, Data3: 0x4a28,
		Data4: [8]byte{0xa5, 0x67, 0x0d, 0xb7, 0x80, 0x06, 0xe6, 0xd7},
	}
	windowsBHIDEnumItems = windows.GUID{
		Data1: 0x94f60519, Data2: 0x2850, Data3: 0x4924,
		Data4: [8]byte{0xaa, 0x5a, 0xd1, 0x5e, 0x84, 0x86, 0x80, 0x39},
	}
	windowsShell32                  = windows.NewLazySystemDLL("shell32.dll")
	windowsProcSHGetKnownFolderItem = windowsShell32.NewProc("SHGetKnownFolderItem")
)

// windowsShellApplicationIdentity contains only a display name and an already
// sanitized package-family identity. Command lines are never requested, and a
// classic executable or shortcut path returned as an AppsFolder parsing name
// is rejected before the item is accumulated in the result slice.
type windowsShellApplicationIdentity struct {
	DisplayName     string
	PackageIdentity string
}

type windowsIShellItem struct {
	vtbl *windowsIShellItemVtbl
}

type windowsIShellItemVtbl struct {
	queryInterface uintptr
	addRef         uintptr
	release        uintptr
	bindToHandler  uintptr
	getParent      uintptr
	getDisplayName uintptr
	getAttributes  uintptr
	compare        uintptr
}

type windowsIEnumShellItems struct {
	vtbl *windowsIEnumShellItemsVtbl
}

type windowsIEnumShellItemsVtbl struct {
	queryInterface uintptr
	addRef         uintptr
	release        uintptr
	next           uintptr
	skip           uintptr
	reset          uintptr
	clone          uintptr
}

// windowsShellApplicationNames inventories launchable applications from the
// current user's virtual AppsFolder. Unlike filesystem Start Menu traversal,
// this covers Store/MSIX/UWP registrations that have no .lnk or classic
// Uninstall entry. Errors degrade silently to the existing application sources.
func windowsShellApplicationNames() []string {
	identities, err := enumerateWindowsShellApplicationIdentities(maxWindowsShellApplications)
	if err != nil {
		return nil
	}
	return collectWindowsShellApplicationNames(identities, maxWindowsApplicationNames)
}

func enumerateWindowsShellApplicationIdentities(limit int) ([]windowsShellApplicationIdentity, error) {
	if limit <= 0 {
		return nil, nil
	}
	if limit > maxWindowsShellApplications {
		limit = maxWindowsShellApplications
	}

	// COM initialization and every interface use must stay on one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	initialized, err := initializeWindowsShellCOM()
	if err != nil {
		return nil, err
	}
	if initialized {
		defer windows.CoUninitialize()
	}

	if err := windowsProcSHGetKnownFolderItem.Find(); err != nil {
		return nil, fmt.Errorf("SHGetKnownFolderItem unavailable: %w", err)
	}
	var folder *windowsIShellItem
	hresult, _, _ := windowsProcSHGetKnownFolderItem.Call(
		uintptr(unsafe.Pointer(windows.FOLDERID_AppsFolder)),
		0, // current-user folder, default lookup flags
		0, // current effective token
		uintptr(unsafe.Pointer(&windowsIIDIShellItem)),
		uintptr(unsafe.Pointer(&folder)),
	)
	if windowsHRESULTFailed(hresult) || folder == nil {
		return nil, fmt.Errorf("SHGetKnownFolderItem(AppsFolder) failed: HRESULT %#x", uint32(hresult))
	}
	defer folder.release()

	enumerator, err := folder.enumItems()
	if err != nil {
		return nil, err
	}
	defer enumerator.release()

	out := make([]windowsShellApplicationIdentity, 0, min(limit, 64))
	for len(out) < limit {
		item, ok, err := enumerator.nextItem()
		if err != nil {
			return out, err
		}
		if !ok {
			break
		}
		displayName := item.displayName(windowsSIGDNNormalDisplay, maxWindowsShellDisplayUTF16)
		packageIdentity := windowsPackageIdentityName(
			item.displayName(windowsSIGDNDesktopAbsoluteParsing, maxWindowsShellParsingUTF16),
		)
		item.release()
		out = append(out, windowsShellApplicationIdentity{
			DisplayName:     displayName,
			PackageIdentity: packageIdentity,
		})
	}
	return out, nil
}

func initializeWindowsShellCOM() (bool, error) {
	err := windows.CoInitializeEx(
		0,
		windows.COINIT_APARTMENTTHREADED|windows.COINIT_DISABLE_OLE1DDE,
	)
	if err == nil {
		return true, nil
	}
	// x/sys represents HRESULT S_FALSE as syscall.Errno(1). COM was already
	// initialized compatibly in that case and still requires CoUninitialize.
	if code, ok := err.(syscall.Errno); ok && uint32(code) == windowsHRESULTFalse {
		return true, nil
	}
	return false, fmt.Errorf("initialize AppsFolder COM apartment: %w", err)
}

func (item *windowsIShellItem) enumItems() (*windowsIEnumShellItems, error) {
	if item == nil || item.vtbl == nil || item.vtbl.bindToHandler == 0 {
		return nil, fmt.Errorf("AppsFolder returned an invalid IShellItem")
	}
	var enumerator *windowsIEnumShellItems
	hresult, _, _ := syscall.SyscallN(
		item.vtbl.bindToHandler,
		uintptr(unsafe.Pointer(item)),
		0,
		uintptr(unsafe.Pointer(&windowsBHIDEnumItems)),
		uintptr(unsafe.Pointer(&windowsIIDIEnumShellItems)),
		uintptr(unsafe.Pointer(&enumerator)),
	)
	runtime.KeepAlive(item)
	if windowsHRESULTFailed(hresult) || enumerator == nil {
		return nil, fmt.Errorf("bind AppsFolder enumerator: HRESULT %#x", uint32(hresult))
	}
	return enumerator, nil
}

func (enumerator *windowsIEnumShellItems) nextItem() (*windowsIShellItem, bool, error) {
	if enumerator == nil || enumerator.vtbl == nil || enumerator.vtbl.next == 0 {
		return nil, false, fmt.Errorf("AppsFolder returned an invalid IEnumShellItems")
	}
	var item *windowsIShellItem
	var fetched uint32
	hresult, _, _ := syscall.SyscallN(
		enumerator.vtbl.next,
		uintptr(unsafe.Pointer(enumerator)),
		1,
		uintptr(unsafe.Pointer(&item)),
		uintptr(unsafe.Pointer(&fetched)),
	)
	runtime.KeepAlive(enumerator)
	if windowsHRESULTFailed(hresult) {
		if item != nil {
			item.release()
		}
		return nil, false, fmt.Errorf("enumerate AppsFolder: HRESULT %#x", uint32(hresult))
	}
	if fetched == 0 || item == nil {
		if item != nil {
			item.release()
		}
		return nil, false, nil
	}
	return item, true, nil
}

func (item *windowsIShellItem) displayName(kind uint32, maxUTF16 int) string {
	if item == nil || item.vtbl == nil || item.vtbl.getDisplayName == 0 || maxUTF16 <= 0 {
		return ""
	}
	var value *uint16
	hresult, _, _ := syscall.SyscallN(
		item.vtbl.getDisplayName,
		uintptr(unsafe.Pointer(item)),
		uintptr(kind),
		uintptr(unsafe.Pointer(&value)),
	)
	runtime.KeepAlive(item)
	if value == nil {
		return ""
	}
	defer windows.CoTaskMemFree(unsafe.Pointer(value))
	if windowsHRESULTFailed(hresult) {
		return ""
	}
	return boundedWindowsUTF16String(value, maxUTF16)
}

func (item *windowsIShellItem) release() {
	if item == nil || item.vtbl == nil || item.vtbl.release == 0 {
		return
	}
	_, _, _ = syscall.SyscallN(item.vtbl.release, uintptr(unsafe.Pointer(item)))
	runtime.KeepAlive(item)
}

func (enumerator *windowsIEnumShellItems) release() {
	if enumerator == nil || enumerator.vtbl == nil || enumerator.vtbl.release == 0 {
		return
	}
	_, _, _ = syscall.SyscallN(enumerator.vtbl.release, uintptr(unsafe.Pointer(enumerator)))
	runtime.KeepAlive(enumerator)
}

func windowsHRESULTFailed(value uintptr) bool {
	return int32(uint32(value)) < 0
}

func boundedWindowsUTF16String(value *uint16, maximum int) string {
	if value == nil || maximum <= 0 {
		return ""
	}
	units := unsafe.Slice(value, maximum+1)
	for i, unit := range units {
		if unit == 0 {
			return windows.UTF16ToString(units[:i])
		}
	}
	// Reject unterminated/oversize Shell metadata instead of retaining a
	// truncated name that could accidentally equal an AI signature.
	return ""
}

func collectWindowsShellApplicationNames(identities []windowsShellApplicationIdentity, limit int) []string {
	if limit <= 0 {
		return nil
	}
	if limit > maxWindowsApplicationNames {
		limit = maxWindowsApplicationNames
	}
	seen := make(map[string]bool)
	out := make([]string, 0, min(limit, len(identities)*2))
	add := func(value string, packageIdentity bool) {
		value = strings.TrimSpace(value)
		key := strings.ToLower(value)
		// The package-id marker is an internal trust boundary. Only the
		// sanitized parsing-name path below may create it; a package-controlled
		// display name must not impersonate another package's stable identity.
		if strings.HasPrefix(key, windowsPackageIdentityPrefix) && !packageIdentity {
			return
		}
		if value == "" || seen[key] || len(out) >= limit {
			return
		}
		seen[key] = true
		out = append(out, value)
	}
	// Give each enumerated app one opportunity before spending the remaining
	// budget on secondary names. Prefer a source-authenticated package identity
	// when present; otherwise keep the display name. This prevents a machine
	// with enough distinct display names to fill the cap from starving every
	// exact Store/MSIX match.
	for _, identity := range identities {
		if len(out) >= limit {
			break
		}
		if identity.PackageIdentity != "" {
			add(identity.PackageIdentity, true)
		} else {
			add(identity.DisplayName, false)
		}
	}
	// In ordinary inventories there is spare capacity, so retain localized
	// display-name matching for packaged apps as a secondary signal too.
	for _, identity := range identities {
		if len(out) >= limit {
			break
		}
		if identity.PackageIdentity != "" {
			add(identity.DisplayName, false)
		}
	}
	return out
}

func withoutReservedWindowsApplicationNames(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), windowsPackageIdentityPrefix) {
			continue
		}
		out = append(out, value)
	}
	return out
}

// windowsPackageIdentityName accepts an AppsFolder AppUserModelID of the form
// "<package-family>!<application-id>" and returns its complete stable package
// family name. Package family names are opaque "<Name>_<PublisherId>" strings;
// retaining PublisherId is essential because package Name alone is not a
// publisher-authenticated identity. Paths, URI-like values, and malformed
// metadata are rejected. The result omits package version, architecture,
// resource ID, install path, and App ID.
func windowsPackageIdentityName(value string) string {
	value = strings.TrimSpace(value)
	for _, prefix := range []string{
		`shell:AppsFolder\`,
		`shell:::{4234d49b-0245-4df3-b780-3893943456e1}\`,
		`::{4234d49b-0245-4df3-b780-3893943456e1}\`,
	} {
		if len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) {
			value = value[len(prefix):]
			break
		}
	}
	if value == "" || len(value) > maxWindowsShellParsingUTF16 || strings.ContainsAny(value, `:/\`) {
		return ""
	}
	if strings.Count(value, "!") != 1 {
		return ""
	}
	family, appID, _ := strings.Cut(value, "!")
	delimiter := strings.LastIndexByte(family, '_')
	if delimiter <= 0 || delimiter == len(family)-1 || !windowsPackageIdentityToken(appID) {
		return ""
	}
	name, publisherID := family[:delimiter], family[delimiter+1:]
	if !windowsPackageIdentityToken(name) || !windowsPackagePublisherID(publisherID) {
		return ""
	}
	return windowsPackageIdentityPrefix + family
}

// PublisherId is the fixed 13-character Crockford-base32 hash embedded in a
// Windows package family name. Validate it separately from the human-authored
// package Name and App ID so a same-name package from another publisher cannot
// inherit a reviewed catalog identity.
func windowsPackagePublisherID(value string) bool {
	if len(value) != 13 {
		return false
	}
	for _, char := range strings.ToLower(value) {
		if (char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'h') ||
			(char >= 'j' && char <= 'k') ||
			(char >= 'm' && char <= 'n') ||
			(char >= 'p' && char <= 't') ||
			(char >= 'v' && char <= 'z') {
			continue
		}
		return false
	}
	return true
}

func windowsPackageIdentityToken(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}
