// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package notify

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var fallbackWriter io.Writer = os.Stderr

const (
	nimAdd        = 0x00000000
	nimModify     = 0x00000001
	nimDelete     = 0x00000002
	nimSetVersion = 0x00000004

	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010
	nifShowTip = 0x00000080

	niifInfo    = 0x00000001
	niifWarning = 0x00000002

	notifyIconVersion4 = 4
	idiApplication     = 32512
)

var (
	notifyShell32               = windows.NewLazySystemDLL("shell32.dll")
	notifyUser32                = windows.NewLazySystemDLL("user32.dll")
	procShellNotifyIconW        = notifyShell32.NewProc("Shell_NotifyIconW")
	procNotifyCreateWindowExW   = notifyUser32.NewProc("CreateWindowExW")
	procNotifyLoadIconW         = notifyUser32.NewProc("LoadIconW")
	defaultWindowsBalloonBroker windowsBalloonBroker
	windowsBalloonSend          = defaultWindowsBalloonBroker.send
)

// notifyIconDataW mirrors NOTIFYICONDATAW. uintptr keeps HWND/HICON aligned
// correctly on both amd64 and arm64 builds; cbSize advertises the exact layout
// compiled for the running architecture.
type notifyIconDataW struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	TimeoutOrVersion uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

type windowsBalloonRequest struct {
	notification Notification
	result       chan error
}

type windowsBalloonBroker struct {
	once     sync.Once
	ready    chan error
	requests chan windowsBalloonRequest
}

// sendPlatform uses an in-process Win32 broker. The executable that owns the
// gateway also owns the notification surface, so packaged builds retain their
// Authenticode identity and no shell child or command interpolation is used.
func sendPlatform(n Notification) error {
	return windowsBalloonSend(n)
}

func (b *windowsBalloonBroker) send(n Notification) error {
	b.once.Do(func() {
		b.ready = make(chan error, 1)
		b.requests = make(chan windowsBalloonRequest, 32)
		go b.run()
	})

	select {
	case err := <-b.ready:
		b.ready <- err // Preserve the one-time result for later callers.
		if err != nil {
			return err
		}
	case <-time.After(2 * time.Second):
		return fmt.Errorf("initialize Windows notification broker: timeout")
	}

	result := make(chan error, 1)
	request := windowsBalloonRequest{notification: n, result: result}
	select {
	case b.requests <- request:
	case <-time.After(2 * time.Second):
		return fmt.Errorf("queue Windows notification: timeout")
	}
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		return fmt.Errorf("deliver Windows notification: timeout")
	}
}

func (b *windowsBalloonBroker) run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hwnd, icon, err := createWindowsNotificationOwner()
	b.ready <- err
	if err != nil {
		return
	}

	var cleanup *time.Timer
	var cleanupC <-chan time.Time
	added := false
	for {
		select {
		case request := <-b.requests:
			err := showWindowsBalloon(hwnd, icon, request.notification, added)
			if err != nil && added {
				// Explorer can restart during a long-running gateway. A failed
				// modify means its notification-area state was lost; re-add once.
				added = false
				err = showWindowsBalloon(hwnd, icon, request.notification, false)
			}
			if err == nil {
				added = true
				if cleanup == nil {
					cleanup = time.NewTimer(time.Minute)
				} else {
					if !cleanup.Stop() {
						select {
						case <-cleanup.C:
						default:
						}
					}
					cleanup.Reset(time.Minute)
				}
				cleanupC = cleanup.C
			}
			request.result <- err
		case <-cleanupC:
			_ = shellNotifyIcon(nimDelete, &notifyIconDataW{
				CbSize: uint32(unsafe.Sizeof(notifyIconDataW{})),
				HWnd:   hwnd,
				UID:    1,
			})
			added = false
			cleanupC = nil
		}
	}
}

func createWindowsNotificationOwner() (uintptr, uintptr, error) {
	className, err := windows.UTF16PtrFromString("STATIC")
	if err != nil {
		return 0, 0, fmt.Errorf("encode notification window class: %w", err)
	}
	windowName, err := windows.UTF16PtrFromString("DefenseClaw notification broker")
	if err != nil {
		return 0, 0, fmt.Errorf("encode notification window name: %w", err)
	}
	// HWND_MESSAGE is (HWND)-3. A message-only owner stays off the taskbar
	// while giving Shell_NotifyIcon a real user-session HWND.
	hwndMessage := ^uintptr(2)
	hwnd, _, callErr := procNotifyCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0,
		0, 0, 0, 0,
		hwndMessage,
		0,
		0,
		0,
	)
	if hwnd == 0 {
		return 0, 0, windowsNotificationCallError("CreateWindowExW", callErr)
	}
	icon, _, callErr := procNotifyLoadIconW.Call(0, idiApplication)
	if icon == 0 {
		return 0, 0, windowsNotificationCallError("LoadIconW", callErr)
	}
	return hwnd, icon, nil
}

func showWindowsBalloon(hwnd, icon uintptr, n Notification, alreadyAdded bool) error {
	data := notifyIconDataW{
		CbSize:      uint32(unsafe.Sizeof(notifyIconDataW{})),
		HWnd:        hwnd,
		UID:         1,
		UFlags:      nifIcon | nifTip | nifInfo | nifShowTip,
		HIcon:       icon,
		DwInfoFlags: windowsNotificationInfoFlags(n),
	}
	copyWindowsNotificationText(data.SzTip[:], "DefenseClaw")
	title := strings.TrimSpace(n.Title)
	if title == "" {
		title = "DefenseClaw"
	}
	if subtitle := strings.TrimSpace(n.Subtitle); subtitle != "" {
		title += " — " + subtitle
	}
	copyWindowsNotificationText(data.SzInfoTitle[:], title)
	copyWindowsNotificationText(data.SzInfo[:], strings.TrimSpace(n.Body))

	action := uint32(nimAdd)
	if alreadyAdded {
		action = nimModify
	}
	if err := shellNotifyIcon(action, &data); err != nil {
		return err
	}
	if !alreadyAdded {
		version := notifyIconDataW{
			CbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
			HWnd:             hwnd,
			UID:              1,
			TimeoutOrVersion: notifyIconVersion4,
		}
		// Version negotiation improves modern notification-center behavior,
		// but a displayed balloon remains successful on older Explorer builds.
		_ = shellNotifyIcon(nimSetVersion, &version)
	}
	return nil
}

func shellNotifyIcon(action uint32, data *notifyIconDataW) error {
	r, _, callErr := procShellNotifyIconW.Call(uintptr(action), uintptr(unsafe.Pointer(data)))
	if r == 0 {
		return windowsNotificationCallError("Shell_NotifyIconW", callErr)
	}
	return nil
}

func windowsNotificationInfoFlags(n Notification) uint32 {
	severity := strings.ToLower(n.Title + " " + n.Subtitle + " " + n.Body)
	if strings.Contains(severity, "block") || strings.Contains(severity, "deny") ||
		strings.Contains(severity, "high") || strings.Contains(severity, "critical") {
		return niifWarning
	}
	return niifInfo
}

func copyWindowsNotificationText(dst []uint16, value string) {
	if len(dst) == 0 {
		return
	}
	value = strings.ReplaceAll(value, "\x00", "�")
	encoded := utf16.Encode([]rune(value))
	limit := len(dst) - 1
	if len(encoded) > limit {
		encoded = encoded[:limit]
		if len(encoded) > 0 && encoded[len(encoded)-1] >= 0xD800 && encoded[len(encoded)-1] <= 0xDBFF {
			encoded = encoded[:len(encoded)-1]
		}
	}
	copy(dst, encoded)
	dst[len(encoded)] = 0
}

func windowsNotificationCallError(name string, err error) error {
	if err == nil || err == syscall.Errno(0) {
		return fmt.Errorf("%s failed", name)
	}
	return fmt.Errorf("%s failed: %w", name, err)
}
