// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

const (
	setupWindowClass = "DefenseClawSetupWizard"

	wmCreate          = 0x0001
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmCommand         = 0x0111
	wmSetFont         = 0x0030
	wmUser            = 0x0400
	wmApp             = 0x8000
	dmGetDefID        = wmUser
	dmSetDefID        = wmUser + 1
	dcHasDefID        = 0x534B
	wmDone            = wmApp + 1

	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsTabStop     = 0x00010000
	wsGroup       = 0x00020000
	wsBorder      = 0x00800000
	wsVScroll     = 0x00200000

	wsExClientEdge    = 0x00000200
	wsExControlParent = 0x00010000

	ssLeft          = 0x00000000
	esReadOnly      = 0x0800
	esAutoHScroll   = 0x0080
	esAutoVScroll   = 0x0040
	esMultiline     = 0x0004
	esWantReturn    = 0x1000
	bsPushButton    = 0x00000000
	bsDefPushButton = 0x00000001
	bsAutoCheckBox  = 0x00000003
	cbsDropDownList = 0x0003
	cbsHasStrings   = 0x0200
	pbsMarquee      = 0x00000008

	cwUseDefault = 0x80000000

	swHide       = 0
	swShow       = 5
	swShowNormal = 1

	colorWindow    = 5
	defaultGUIFont = 17

	bmGetCheck = 0x00F0
	bmSetCheck = 0x00F1
	bstChecked = 1

	cbAddString  = 0x0143
	cbGetCurSel  = 0x0147
	cbSetCurSel  = 0x014E
	cbnSelChange = 1

	pbmSetMarquee = wmUser + 10

	idPrimary     = 1
	idCancel      = 2
	idConnector   = 1001
	idMode        = 1002
	idStart       = 1003
	idDeleteData  = 1004
	idOpenTerm    = 1007
	idProgress    = 1008
	idDescription = 1009
	idPath        = 1010
	idHeading     = 1011
	idOpenLog     = 1012
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	comctl32 = windows.NewLazySystemDLL("comctl32.dll")

	procRegisterClassEx      = user32.NewProc("RegisterClassExW")
	procCreateWindowEx       = user32.NewProc("CreateWindowExW")
	procDefWindowProc        = user32.NewProc("DefWindowProcW")
	procDestroyWindow        = user32.NewProc("DestroyWindow")
	procDispatchMessage      = user32.NewProc("DispatchMessageW")
	procEnableWindow         = user32.NewProc("EnableWindow")
	procGetMessage           = user32.NewProc("GetMessageW")
	procGetSystemMetrics     = user32.NewProc("GetSystemMetrics")
	procIsDialogMessage      = user32.NewProc("IsDialogMessageW")
	procLoadCursor           = user32.NewProc("LoadCursorW")
	procMessageBox           = user32.NewProc("MessageBoxW")
	procPostMessage          = user32.NewProc("PostMessageW")
	procSendMessage          = user32.NewProc("SendMessageW")
	procSetWindowText        = user32.NewProc("SetWindowTextW")
	procSetWindowPos         = user32.NewProc("SetWindowPos")
	procSetFocus             = user32.NewProc("SetFocus")
	procShowWindow           = user32.NewProc("ShowWindow")
	procShutdownBlockCreate  = user32.NewProc("ShutdownBlockReasonCreate")
	procShutdownBlockDestroy = user32.NewProc("ShutdownBlockReasonDestroy")
	procTranslateMessage     = user32.NewProc("TranslateMessage")
	procUpdateWindow         = user32.NewProc("UpdateWindow")

	procGetModuleHandle    = kernel32.NewProc("GetModuleHandleW")
	procGetSystemDirectory = kernel32.NewProc("GetSystemDirectoryW")
	procGetStockObject     = gdi32.NewProc("GetStockObject")
	procShellExecute       = shell32.NewProc("ShellExecuteW")
	procInitCommonControls = comctl32.NewProc("InitCommonControls")
)

type point struct {
	X int32
	Y int32
}

type msg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSmall  uintptr
}

type setupWizard struct {
	hwnd        uintptr
	opts        options
	installRoot string
	dataRoot    string

	heading        uintptr
	description    uintptr
	pathLabel      uintptr
	pathEdit       uintptr
	connectorLabel uintptr
	connector      uintptr
	modeLabel      uintptr
	mode           uintptr
	start          uintptr
	deleteData     uintptr
	progress       uintptr
	primary        uintptr
	cancel         uintptr
	openTerm       uintptr
	openLog        uintptr
	logPath        string

	running         bool
	done            bool
	cancelRequested bool
	operationCancel context.CancelFunc
	code            int
	err             error
	mu              sync.Mutex
}

type wizardChoice struct {
	Label string
	Value string
}

var (
	wizardConnectorChoices = []wizardChoice{
		{Label: "Configure later", Value: "none"},
		{Label: "Codex CLI", Value: "codex"},
		{Label: "Claude Code", Value: "claudecode"},
	}
	wizardModeChoices = []wizardChoice{
		{Label: "Observe", Value: "observe"},
		{Label: "Action", Value: "action"},
	}
)

var (
	wizardsMu sync.Mutex
	wizards   = map[uintptr]*setupWizard{}
)

func runInteractiveWizard(opts options, installRoot, dataRoot string) (int, error) {
	// A Win32 window and its message queue belong to the OS thread that
	// creates them. Keep creation, GetMessage, and DispatchMessage on that
	// thread; otherwise the Go scheduler may resume this goroutine on another
	// thread whose empty queue never receives the wizard's window messages.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if opts.Action == "install" {
		opts = interactiveInstallOptions(opts, installRoot)
	}
	wiz := &setupWizard{
		opts:        opts,
		installRoot: installRoot,
		dataRoot:    dataRoot,
		code:        userExitCode,
	}
	if err := registerSetupWindowClass(); err != nil {
		return 1, err
	}
	title := "DefenseClaw Setup"
	if opts.Action == "repair" {
		title = "Repair DefenseClaw"
	} else if opts.Action == "upgrade" {
		title = "Upgrade DefenseClaw"
	} else if opts.Action == "uninstall" {
		title = "Uninstall DefenseClaw"
	}
	hInstance, _, _ := procGetModuleHandle.Call(0)
	className := windows.StringToUTF16Ptr(setupWindowClass)
	windowTitle := windows.StringToUTF16Ptr(title)
	hwnd, _, err := procCreateWindowEx.Call(
		wsExControlParent,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		wsOverlapped|wsCaption|wsSysMenu|wsMinimizeBox,
		cwUseDefault,
		cwUseDefault,
		560,
		420,
		0,
		0,
		hInstance,
		0,
	)
	runtime.KeepAlive(className)
	runtime.KeepAlive(windowTitle)
	if hwnd == 0 {
		return 1, fmt.Errorf("create setup wizard window: %w", err)
	}
	wiz.hwnd = hwnd
	wizardsMu.Lock()
	wizards[hwnd] = wiz
	wizardsMu.Unlock()

	if err := wiz.createControls(); err != nil {
		return 1, err
	}
	wiz.showOptions()
	centerWindow(hwnd, 560, 420)
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
	if opts.Action == "install" {
		procSetFocus.Call(wiz.connector)
	} else {
		procSetFocus.Call(wiz.primary)
	}

	var message msg
	for {
		ret, _, getErr := procGetMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		switch int32(ret) {
		case -1:
			return 1, fmt.Errorf("message loop failed: %w", getErr)
		case 0:
			wiz.mu.Lock()
			code, resultErr := wiz.code, wiz.err
			wiz.mu.Unlock()
			return code, resultErr
		default:
			handled, _, _ := procIsDialogMessage.Call(hwnd, uintptr(unsafe.Pointer(&message)))
			if handled != 0 {
				continue
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
			procDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
		}
	}
}

func registerSetupWindowClass() error {
	hInstance, _, _ := procGetModuleHandle.Call(0)
	cursor, _, _ := procLoadCursor.Call(0, 32512)
	className := windows.StringToUTF16Ptr(setupWindowClass)
	wc := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:    syscall.NewCallback(setupWndProc),
		Instance:   hInstance,
		Cursor:     cursor,
		Background: colorWindow + 1,
		ClassName:  className,
	}
	ret, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
	if ret == 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == 1410 {
			return nil
		}
		return fmt.Errorf("register setup wizard window: %w", err)
	}
	procInitCommonControls.Call()
	return nil
}

func setupWndProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	wiz := wizardFor(hwnd)
	switch message {
	case dmGetDefID:
		return uintptr(dcHasDefID<<16 | idPrimary)
	case dmSetDefID:
		// The wizard has one stable default action. IsDialogMessageW still sends
		// focus/navigation updates, but cannot replace that action with a child
		// control ID that has no command handler.
		return 1
	case wmCommand:
		if wiz != nil {
			wiz.handleCommand(lowWord(uint32(wParam)), highWord(uint32(wParam)))
			return 0
		}
	case wmClose:
		if wiz != nil && wiz.running {
			wiz.requestCancellation()
			return 0
		}
		procDestroyWindow.Call(hwnd)
		return 0
	case wmQueryEndSession:
		if wiz != nil && wiz.running {
			// Request a bounded shutdown delay while the active operation reaches a
			// durable boundary. Windows may still end a critical session; the
			// transaction journal then drives idempotent recovery on the next run.
			setShutdownBlockReason(hwnd, "DefenseClaw Setup is committing an installation transaction.")
			return 0
		}
		return 1
	case wmEndSession:
		// No unbounded cleanup belongs in the session-ending callback. A forced
		// end is recovered from the fsynced transaction journal on the next run.
		return 0
	case wmDone:
		if wiz != nil {
			wiz.finish()
			return 0
		}
	case wmDestroy:
		procShutdownBlockDestroy.Call(hwnd)
		wizardsMu.Lock()
		delete(wizards, hwnd)
		wizardsMu.Unlock()
		user32.NewProc("PostQuitMessage").Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
	return ret
}

func (w *setupWizard) createControls() error {
	font, _, _ := procGetStockObject.Call(defaultGUIFont)
	w.heading = w.control("STATIC", "", wsChild|wsVisible|ssLeft, 24, 22, 500, 26, idHeading)
	w.description = w.controlEx(wsExClientEdge, "EDIT", "", wsChild|wsVisible|wsTabStop|wsVScroll|esReadOnly|esMultiline|esAutoVScroll|esWantReturn, 24, 58, 500, 70, idDescription)
	w.pathLabel = w.control("STATIC", "&Install location", wsChild|wsVisible|ssLeft, 24, 130, 180, 18, 0)
	w.pathEdit = w.controlEx(wsExClientEdge, "EDIT", w.installRoot, wsChild|wsVisible|wsTabStop|wsBorder|esReadOnly|esAutoHScroll, 24, 150, 500, 24, idPath)
	w.connectorLabel = w.control("STATIC", "&Connector", wsChild|wsVisible|ssLeft, 24, 178, 180, 18, 0)
	w.connector = w.control("COMBOBOX", "", wsChild|wsVisible|wsTabStop|cbsDropDownList|cbsHasStrings, 24, 198, 230, 160, idConnector)
	w.modeLabel = w.control("STATIC", "&Mode", wsChild|wsVisible|ssLeft, 294, 178, 180, 18, 0)
	w.mode = w.control("COMBOBOX", "", wsChild|wsVisible|wsTabStop|cbsDropDownList|cbsHasStrings, 294, 198, 230, 160, idMode)
	w.start = w.control("BUTTON", "&Start gateway now and at sign-in", wsChild|wsVisible|wsTabStop|bsAutoCheckBox, 24, 244, 300, 24, idStart)
	w.deleteData = w.control("BUTTON", "&Delete user data under %USERPROFILE%\\.defenseclaw", wsChild|wsVisible|wsTabStop|bsAutoCheckBox, 24, 244, 430, 24, idDeleteData)
	w.progress = w.control("msctls_progress32", "", wsChild|pbsMarquee, 24, 286, 500, 20, idProgress)
	w.primary = w.control("BUTTON", "", wsChild|wsVisible|wsTabStop|wsGroup|bsDefPushButton, 300, 334, 100, 30, idPrimary)
	w.openTerm = w.control("BUTTON", "Open &Terminal", wsChild|wsTabStop|bsPushButton, 284, 334, 116, 30, idOpenTerm)
	w.openLog = w.control("BUTTON", "Open &Log", wsChild|wsTabStop|bsPushButton, 284, 334, 116, 30, idOpenLog)
	w.cancel = w.control("BUTTON", "&Cancel", wsChild|wsVisible|wsTabStop|bsPushButton, 416, 334, 100, 30, idCancel)
	for _, hwnd := range []uintptr{w.heading, w.description, w.pathLabel, w.pathEdit, w.connectorLabel, w.connector, w.modeLabel, w.mode, w.start, w.deleteData, w.progress, w.primary, w.openTerm, w.openLog, w.cancel} {
		if hwnd == 0 {
			return fmt.Errorf("create setup wizard control failed")
		}
		procSendMessage.Call(hwnd, wmSetFont, font, 1)
	}
	for _, choice := range wizardConnectorChoices {
		procSendMessage.Call(w.connector, cbAddString, 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(choice.Label))))
	}
	procSendMessage.Call(w.connector, cbSetCurSel, uintptr(connectorIndex(w.opts.Connector)), 0)
	for _, choice := range wizardModeChoices {
		procSendMessage.Call(w.mode, cbAddString, 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(choice.Label))))
	}
	procSendMessage.Call(w.mode, cbSetCurSel, uintptr(modeIndex(w.opts.Mode)), 0)
	if w.opts.StartGateway {
		procSendMessage.Call(w.start, bmSetCheck, bstChecked, 0)
	}
	w.syncGatewayChoice()
	if w.opts.DeleteUserData {
		procSendMessage.Call(w.deleteData, bmSetCheck, bstChecked, 0)
	}
	return nil
}

func (w *setupWizard) control(class, text string, style uintptr, x, y, width, height int32, id uintptr) uintptr {
	return w.controlEx(0, class, text, style, x, y, width, height, id)
}

func (w *setupWizard) controlEx(exStyle uintptr, class, text string, style uintptr, x, y, width, height int32, id uintptr) uintptr {
	className := windows.StringToUTF16Ptr(class)
	windowText := windows.StringToUTF16Ptr(text)
	hwnd, _, _ := procCreateWindowEx.Call(
		exStyle,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowText)),
		style,
		uintptr(x),
		uintptr(y),
		uintptr(width),
		uintptr(height),
		w.hwnd,
		id,
		0,
		0,
	)
	runtime.KeepAlive(className)
	runtime.KeepAlive(windowText)
	return hwnd
}

func (w *setupWizard) showOptions() {
	setText(w.heading, w.headingText())
	setText(w.description, w.descriptionText())
	setText(w.pathEdit, w.installRoot)
	if w.opts.Action == "uninstall" {
		setText(w.primary, "Uninstall")
		w.show(w.connectorLabel, false)
		w.show(w.connector, false)
		w.show(w.modeLabel, false)
		w.show(w.mode, false)
		w.show(w.start, false)
		w.show(w.deleteData, true)
	} else if w.opts.Action == "repair" || w.opts.Action == "upgrade" {
		setText(w.primary, primaryLabel(w.opts.Action))
		w.show(w.connectorLabel, false)
		w.show(w.connector, false)
		w.show(w.modeLabel, false)
		w.show(w.mode, false)
		w.show(w.start, false)
		w.show(w.deleteData, false)
	} else {
		setText(w.primary, primaryLabel(w.opts.Action))
		w.show(w.connectorLabel, true)
		w.show(w.connector, true)
		w.show(w.modeLabel, true)
		w.show(w.mode, true)
		w.show(w.start, true)
		w.show(w.deleteData, false)
	}
	w.show(w.progress, false)
	w.show(w.openTerm, false)
	w.show(w.openLog, false)
	w.show(w.primary, true)
	w.show(w.cancel, true)
}

func (w *setupWizard) headingText() string {
	switch w.opts.Action {
	case "repair":
		return "Repair DefenseClaw"
	case "upgrade":
		return "Upgrade DefenseClaw"
	case "uninstall":
		return "Uninstall DefenseClaw"
	default:
		return "Install DefenseClaw"
	}
}

func (w *setupWizard) descriptionText() string {
	switch w.opts.Action {
	case "repair":
		return "Repair reinstalls the packaged DefenseClaw files without resetting your configuration, connector settings, or audit history."
	case "upgrade":
		return "Upgrade replaces the product files through the installer transaction while preserving your DefenseClaw data."
	case "uninstall":
		return "Uninstall removes product-owned application files, installer cache, Installed Apps registration, and the user PATH entry. User data is preserved unless you opt in below."
	default:
		return "This setup wizard installs the DefenseClaw CLI/TUI, native gateway, hook launcher, and embedded managed Python runtime for the current Windows user."
	}
}

func primaryLabel(action string) string {
	switch action {
	case "repair":
		return "Repair"
	case "upgrade":
		return "Upgrade"
	default:
		return "Install"
	}
}

func (w *setupWizard) handleCommand(id, notification uint16) {
	switch id {
	case idConnector:
		if notification == cbnSelChange {
			w.syncGatewayChoice()
		}
	case idPrimary:
		if w.done {
			procDestroyWindow.Call(w.hwnd)
			return
		}
		if !w.running {
			w.startAction()
		}
	case idCancel:
		if w.running {
			w.requestCancellation()
		} else {
			w.mu.Lock()
			w.code = userExitCode
			w.mu.Unlock()
			procDestroyWindow.Call(w.hwnd)
		}
	case idOpenTerm:
		w.openTerminal()
	case idOpenLog:
		w.openSetupLog()
	}
}

func (w *setupWizard) syncGatewayChoice() {
	required := connectorValue(selection(w.connector)) != "none"
	if required {
		procSendMessage.Call(w.start, bmSetCheck, bstChecked, 0)
		setText(w.start, "Gateway starts at sign-in (required for selected connector)")
	} else {
		setText(w.start, "Start gateway now and at sign-in")
	}
	procEnableWindow.Call(w.start, boolToUintptr(!required))
}

func (w *setupWizard) startAction() {
	w.running = true
	operationContext, operationCancel := context.WithCancel(context.Background())
	w.operationCancel = operationCancel
	w.cancelRequested = false
	setShutdownBlockReason(w.hwnd, "DefenseClaw Setup is committing an installation transaction.")
	w.opts.Quiet = true
	if w.opts.Action == "uninstall" {
		w.opts.DeleteUserData = checked(w.deleteData)
		setText(w.description, "Removing DefenseClaw application files...")
	} else {
		if w.opts.Action == "install" {
			w.opts = optionsFromWizardSelections(
				w.opts,
				selection(w.connector),
				selection(w.mode),
				checked(w.start),
			)
		}
		setText(w.description, "Installing packaged files and updating user registration...")
	}
	setText(w.heading, "Working")
	w.enableInputs(false)
	// Keep cancellation available while the worker advances to a rollback-safe
	// journal boundary. The window remains open until rollback has completed.
	procEnableWindow.Call(w.cancel, 1)
	w.show(w.progress, true)
	procSendMessage.Call(w.progress, pbmSetMarquee, 1, 30)
	go func(ctx context.Context, cancel context.CancelFunc, opts options) {
		defer cancel()
		var code int
		var err error
		if opts.Action == "uninstall" {
			code, err = runUninstallContext(ctx, opts, w.installRoot, w.dataRoot)
		} else {
			code, err = runInstallContext(ctx, opts, w.installRoot, w.dataRoot)
		}
		w.mu.Lock()
		w.code = code
		w.err = err
		w.mu.Unlock()
		procPostMessage.Call(w.hwnd, wmDone, 0, 0)
	}(operationContext, operationCancel, w.opts)
}

func (w *setupWizard) requestCancellation() {
	if !w.running || w.cancelRequested {
		return
	}
	const (
		mbYesNo        = 0x00000004
		mbIconQuestion = 0x00000020
		mbDefButton2   = 0x00000100
		idYes          = 6
	)
	answer := messageBoxResult(
		w.hwnd,
		"Cancel Setup at the next safe point?\r\n\r\nUncommitted changes will be rolled back before this window closes. If the transaction is already committed, Setup must finish its durable recovery steps.",
		"Cancel DefenseClaw Setup",
		mbYesNo|mbIconQuestion|mbDefButton2,
	)
	if answer != idYes {
		return
	}
	w.cancelRequested = true
	setText(w.heading, "Cancelling")
	setText(w.description, "Stopping the active child process tree and rolling back at the next safe transaction boundary...")
	procEnableWindow.Call(w.cancel, 0)
	if w.operationCancel != nil {
		w.operationCancel()
	}
}

func (w *setupWizard) finish() {
	w.running = false
	w.operationCancel = nil
	procShutdownBlockDestroy.Call(w.hwnd)
	w.done = true
	w.enableInputs(false)
	w.show(w.progress, false)
	w.show(w.cancel, false)
	w.move(w.primary, 416, 334, 100, 30)
	setText(w.primary, "Finish")
	procEnableWindow.Call(w.primary, 1)
	w.mu.Lock()
	code, resultErr := w.code, w.err
	w.mu.Unlock()
	logPath, logErr := writeWizardLog(w.opts.Action, code, resultErr)
	if logErr == nil {
		w.logPath = logPath
	}
	if resultErr != nil {
		if wizardCancellationCompleted(code, resultErr) {
			setText(w.heading, "Setup was cancelled")
			setText(w.description, "The operation was cancelled and every uncommitted change was rolled back. The private setup log records the final durable transaction state.")
			w.show(w.openTerm, false)
			w.show(w.openLog, w.logPath != "")
			procEnableWindow.Call(w.openLog, boolToUintptr(w.logPath != ""))
			return
		}
		setText(w.heading, "Setup could not finish")
		message := wizardFailureDescription(code, resultErr, w.logPath, logErr)
		setText(w.description, message)
		w.show(w.openTerm, false)
		w.show(w.openLog, w.logPath != "")
		procEnableWindow.Call(w.openLog, boolToUintptr(w.logPath != ""))
		return
	}
	w.show(w.openLog, false)
	w.show(w.openTerm, w.opts.Action != "uninstall")
	procEnableWindow.Call(w.openTerm, boolToUintptr(w.opts.Action != "uninstall"))
	switch w.opts.Action {
	case "uninstall":
		setText(w.heading, "DefenseClaw was removed")
		if w.opts.DeleteUserData {
			setText(w.description, "DefenseClaw application files and user data were removed.")
		} else {
			setText(w.description, "DefenseClaw application files were removed. Configuration, connector backups, and audit history were preserved under %USERPROFILE%\\.defenseclaw.")
		}
	default:
		setText(w.heading, "DefenseClaw is installed")
		setText(w.description, wizardCompletionDescription(w.opts.Connector))
	}
}

func wizardCancellationCompleted(code int, err error) bool {
	return code == userExitCode && errors.Is(err, errSetupCancelled)
}

func wizardCompletionDescription(connector string) string {
	const installed = " Run defenseclaw to open the TUI and review activity. DefenseClaw is a CLI/TUI product; setup did not install a separate GUI application."
	switch connector {
	case "codex":
		return "Codex CLI is configured and the DefenseClaw hooks are trusted automatically." + installed
	case "claudecode":
		return "Claude Code is configured and its native Windows hooks are ready." + installed
	default:
		return "Open a terminal and run defenseclaw init when you are ready to configure Codex, Claude Code, or another connector." + installed
	}
}

func (w *setupWizard) enableInputs(enabled bool) {
	for _, hwnd := range []uintptr{w.pathEdit, w.connector, w.mode, w.start, w.deleteData, w.primary, w.cancel, w.openTerm, w.openLog} {
		procEnableWindow.Call(hwnd, boolToUintptr(enabled))
	}
}

func (w *setupWizard) move(hwnd uintptr, x, y, width, height int32) {
	procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(width), uintptr(height), 0x0004)
}

func (w *setupWizard) show(hwnd uintptr, show bool) {
	if show {
		procShowWindow.Call(hwnd, swShow)
		return
	}
	procShowWindow.Call(hwnd, swHide)
}

func (w *setupWizard) openTerminal() {
	commandDir := filepath.Join(w.installRoot, "bin")
	launcher := filepath.Join(commandDir, "defenseclaw.exe")
	powerShell, err := systemPowerShellPath()
	if err != nil {
		messageBox(w.hwnd, "Setup could not locate the system PowerShell. Open a new terminal and run defenseclaw.", "DefenseClaw Setup", 0x30)
		return
	}
	verb := windows.StringToUTF16Ptr("open")
	file := windows.StringToUTF16Ptr(powerShell)
	params := windows.StringToUTF16Ptr(terminalPowerShellParams(launcher))
	dir := windows.StringToUTF16Ptr(commandDir)
	ret, _, _ := procShellExecute.Call(w.hwnd, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(dir)), swShowNormal)
	runtime.KeepAlive(verb)
	runtime.KeepAlive(file)
	runtime.KeepAlive(params)
	runtime.KeepAlive(dir)
	if ret <= 32 {
		messageBox(w.hwnd, "Setup could not open PowerShell. Open a new terminal and run defenseclaw.", "DefenseClaw Setup", 0x30)
	}
}

func terminalPowerShellParams(launcher string) string {
	return "-NoExit -NoProfile -Command \"& '" + strings.ReplaceAll(launcher, "'", "''") + "'\""
}

func (w *setupWizard) openSetupLog() {
	if w.logPath == "" {
		return
	}
	verb := windows.StringToUTF16Ptr("open")
	file := windows.StringToUTF16Ptr(w.logPath)
	ret, _, _ := procShellExecute.Call(
		w.hwnd,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		0,
		0,
		swShowNormal,
	)
	runtime.KeepAlive(verb)
	runtime.KeepAlive(file)
	if ret <= 32 {
		messageBox(w.hwnd, "Setup could not open the log. Copy the log path from the error details and open it manually.", "DefenseClaw Setup", 0x30)
	}
}

func setShutdownBlockReason(hwnd uintptr, reason string) {
	value := windows.StringToUTF16Ptr(reason)
	procShutdownBlockCreate.Call(hwnd, uintptr(unsafe.Pointer(value)))
	runtime.KeepAlive(value)
}

func writeWizardLog(action string, code int, resultErr error) (string, error) {
	root, err := defaultTransactionRoot()
	if err != nil {
		return "", err
	}
	phase := "none"
	journal, journalErr := readSetupJournal(journalPaths(root).Journal)
	if journalErr != nil {
		phase = "unreadable: " + boundedReconciliationMessage(journalErr.Error())
	} else if journal != nil {
		phase = journal.Phase
	}
	result := "success"
	detail := "none"
	if resultErr != nil {
		result = "failure"
		detail = resultErr.Error()
	}
	contents := fmt.Sprintf(
		"DefenseClaw Setup\r\nTime (UTC): %s\r\nProcess: %d\r\nAction: %s\r\nResult: %s\r\nExit code: %d\r\nTransaction journal: %s\r\n\r\n%s\r\n",
		time.Now().UTC().Format(time.RFC3339),
		os.Getpid(),
		action,
		result,
		code,
		phase,
		detail,
	)
	path := filepath.Join(root, "setup.log")
	if err := safefile.WritePrivate(path, []byte(contents)); err != nil {
		return "", err
	}
	return path, nil
}

func wizardFailureDescription(code int, resultErr error, logPath string, logErr error) string {
	state := "Any committed file transition is recorded in the durable setup journal and will be recovered automatically when Setup runs again."
	if strings.Contains(resultErr.Error(), "core installation completed") || strings.Contains(resultErr.Error(), "core uninstall completed") {
		state = "The core product transaction completed; only the connector reconciliation named below remains pending."
	}
	message := fmt.Sprintf("Exit code: %d\r\n%s\r\n\r\n%v", code, state, resultErr)
	if code == retryRequiredCode {
		message += "\r\n\r\nClose running DefenseClaw or agent terminals, correct the reported condition, and run Setup again."
	}
	if logPath != "" {
		message += "\r\n\r\nLog: " + logPath
	} else if logErr != nil {
		message += "\r\n\r\nThe private setup log could not be written: " + logErr.Error()
	}
	return message
}

func systemPowerShellPath() (string, error) {
	buffer := make([]uint16, 32768)
	ret, _, err := procGetSystemDirectory.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if ret == 0 || int(ret) >= len(buffer) {
		return "", fmt.Errorf("GetSystemDirectoryW failed: %w", err)
	}
	return filepath.Join(windows.UTF16ToString(buffer[:ret]), "WindowsPowerShell", "v1.0", "powershell.exe"), nil
}

func wizardFor(hwnd uintptr) *setupWizard {
	wizardsMu.Lock()
	defer wizardsMu.Unlock()
	return wizards[hwnd]
}

func setText(hwnd uintptr, text string) {
	procSetWindowText.Call(hwnd, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))))
}

func selection(hwnd uintptr) int {
	ret, _, _ := procSendMessage.Call(hwnd, cbGetCurSel, 0, 0)
	return int(ret)
}

func checked(hwnd uintptr) bool {
	ret, _, _ := procSendMessage.Call(hwnd, bmGetCheck, 0, 0)
	return ret == bstChecked
}

func connectorIndex(value string) int {
	return wizardChoiceIndex(wizardConnectorChoices, value)
}

func connectorValue(index int) string {
	return wizardChoiceValue(wizardConnectorChoices, index)
}

func modeIndex(value string) int {
	return wizardChoiceIndex(wizardModeChoices, value)
}

func modeValue(index int) string {
	return wizardChoiceValue(wizardModeChoices, index)
}

func wizardChoiceIndex(choices []wizardChoice, value string) int {
	for index, choice := range choices {
		if choice.Value == value {
			return index
		}
	}
	return 0
}

func wizardChoiceValue(choices []wizardChoice, index int) string {
	if index >= 0 && index < len(choices) {
		return choices[index].Value
	}
	return choices[0].Value
}

func optionsFromWizardSelections(opts options, connectorSelection, modeSelection int, startGateway bool) options {
	opts.Quiet = true
	opts.Connector = connectorValue(connectorSelection)
	opts.Mode = modeValue(modeSelection)
	opts.StartGateway = startGateway || opts.Connector != "none"
	opts.ConnectorSet = true
	opts.ModeSet = true
	opts.StartGatewaySet = true
	return opts
}

func interactiveInstallOptions(opts options, installRoot string) options {
	state, err := loadExistingInstallState(installRoot)
	if err != nil {
		// runInstall reports invalid or unsafe installer state inside the wizard,
		// where a windowsgui build can show the failure to the user.
		return opts
	}
	if state == nil {
		return applyInteractiveInstallDefaults(opts, nil, false, false)
	}
	gatewayPath := filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe")
	autoStart, autoStartErr := gatewayAutoStartConfigured(gatewayPath)
	return applyInteractiveInstallDefaults(opts, state, autoStart, autoStartErr == nil)
}

func applyInteractiveInstallDefaults(opts options, state *installState, autoStart, autoStartKnown bool) options {
	if state == nil {
		if !opts.StartGatewaySet {
			opts.StartGateway = true
		}
		return opts
	}
	if !opts.ConnectorSet && validConnector(state.Connector) {
		opts.Connector = state.Connector
	}
	if !opts.ModeSet && validMode(state.Mode) {
		opts.Mode = state.Mode
	}
	if !opts.StartGatewaySet {
		if autoStartKnown {
			opts.StartGateway = autoStart
		}
		// Hook connectors require the gateway even when an older installation
		// has lost its Run-key registration. Repair should restore that invariant.
		opts.StartGateway = opts.StartGateway || opts.Connector != "none"
	}
	return opts
}

func centerWindow(hwnd uintptr, width, height int32) {
	screenW, _, _ := procGetSystemMetrics.Call(0)
	screenH, _, _ := procGetSystemMetrics.Call(1)
	x := (int32(screenW) - width) / 2
	y := (int32(screenH) - height) / 2
	procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(width), uintptr(height), 0)
}

func messageBoxResult(hwnd uintptr, text, title string, flags uintptr) uintptr {
	textPtr := windows.StringToUTF16Ptr(text)
	titlePtr := windows.StringToUTF16Ptr(title)
	result, _, _ := procMessageBox.Call(
		hwnd,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		flags,
	)
	runtime.KeepAlive(textPtr)
	runtime.KeepAlive(titlePtr)
	return result
}

func messageBox(hwnd uintptr, text, title string, flags uintptr) {
	_ = messageBoxResult(hwnd, text, title, flags)
}

func boolToUintptr(value bool) uintptr {
	if value {
		return 1
	}
	return 0
}

func lowWord(value uint32) uint16 {
	return uint16(value & 0xffff)
}

func highWord(value uint32) uint16 {
	return uint16((value >> 16) & 0xffff)
}
