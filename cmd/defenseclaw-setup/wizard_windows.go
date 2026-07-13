// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	setupWindowClass = "DefenseClawSetupWizard"

	wmCreate  = 0x0001
	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmCommand = 0x0111
	wmSetFont = 0x0030
	wmUser    = 0x0400
	wmDone    = wmUser + 1

	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsTabStop     = 0x00010000
	wsGroup       = 0x00020000
	wsBorder      = 0x00800000

	wsExClientEdge    = 0x00000200
	wsExControlParent = 0x00010000

	ssLeft          = 0x00000000
	esReadOnly      = 0x0800
	esAutoHScroll   = 0x0080
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

	idConnector   = 1001
	idMode        = 1002
	idStart       = 1003
	idDeleteData  = 1004
	idPrimary     = 1005
	idCancel      = 1006
	idOpenTerm    = 1007
	idProgress    = 1008
	idDescription = 1009
	idPath        = 1010
	idHeading     = 1011
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	comctl32 = windows.NewLazySystemDLL("comctl32.dll")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procGetMessage       = user32.NewProc("GetMessageW")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procLoadCursor       = user32.NewProc("LoadCursorW")
	procMessageBox       = user32.NewProc("MessageBoxW")
	procPostMessage      = user32.NewProc("PostMessageW")
	procSendMessage      = user32.NewProc("SendMessageW")
	procSetWindowText    = user32.NewProc("SetWindowTextW")
	procSetWindowPos     = user32.NewProc("SetWindowPos")
	procShowWindow       = user32.NewProc("ShowWindow")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procUpdateWindow     = user32.NewProc("UpdateWindow")

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

	running bool
	done    bool
	code    int
	err     error
	mu      sync.Mutex
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
	case wmCommand:
		if wiz != nil {
			wiz.handleCommand(lowWord(uint32(wParam)), highWord(uint32(wParam)))
			return 0
		}
	case wmClose:
		if wiz != nil && wiz.running {
			messageBox(hwnd, "Setup is still running. Wait for it to finish before closing this window.", "DefenseClaw Setup", 0x40)
			return 0
		}
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDone:
		if wiz != nil {
			wiz.finish()
			return 0
		}
	case wmDestroy:
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
	w.description = w.control("STATIC", "", wsChild|wsVisible|ssLeft, 24, 58, 500, 78, idDescription)
	w.pathLabel = w.control("STATIC", "Install location", wsChild|wsVisible|ssLeft, 24, 130, 180, 18, 0)
	w.pathEdit = w.controlEx(wsExClientEdge, "EDIT", w.installRoot, wsChild|wsVisible|wsBorder|esReadOnly|esAutoHScroll, 24, 150, 500, 24, idPath)
	w.connectorLabel = w.control("STATIC", "Connector", wsChild|wsVisible|ssLeft, 24, 178, 180, 18, 0)
	w.connector = w.control("COMBOBOX", "", wsChild|wsVisible|wsTabStop|cbsDropDownList|cbsHasStrings, 24, 198, 230, 160, idConnector)
	w.modeLabel = w.control("STATIC", "Mode", wsChild|wsVisible|ssLeft, 294, 178, 180, 18, 0)
	w.mode = w.control("COMBOBOX", "", wsChild|wsVisible|wsTabStop|cbsDropDownList|cbsHasStrings, 294, 198, 230, 160, idMode)
	w.start = w.control("BUTTON", "Start gateway now and at sign-in", wsChild|wsVisible|wsTabStop|bsAutoCheckBox, 24, 244, 300, 24, idStart)
	w.deleteData = w.control("BUTTON", "Delete user data under %USERPROFILE%\\.defenseclaw", wsChild|wsVisible|wsTabStop|bsAutoCheckBox, 24, 244, 430, 24, idDeleteData)
	w.progress = w.control("msctls_progress32", "", wsChild|pbsMarquee, 24, 286, 500, 20, idProgress)
	w.primary = w.control("BUTTON", "", wsChild|wsVisible|wsTabStop|wsGroup|bsDefPushButton, 300, 334, 100, 30, idPrimary)
	w.openTerm = w.control("BUTTON", "Open Terminal", wsChild|wsTabStop|bsPushButton, 284, 334, 116, 30, idOpenTerm)
	w.cancel = w.control("BUTTON", "Cancel", wsChild|wsVisible|wsTabStop|bsPushButton, 416, 334, 100, 30, idCancel)
	for _, hwnd := range []uintptr{w.heading, w.description, w.pathLabel, w.pathEdit, w.connectorLabel, w.connector, w.modeLabel, w.mode, w.start, w.deleteData, w.progress, w.primary, w.openTerm, w.cancel} {
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
		if !w.running {
			w.mu.Lock()
			w.code = userExitCode
			w.mu.Unlock()
			procDestroyWindow.Call(w.hwnd)
		}
	case idOpenTerm:
		w.openTerminal()
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
	w.show(w.progress, true)
	procSendMessage.Call(w.progress, pbmSetMarquee, 1, 30)
	go func(opts options) {
		var code int
		var err error
		if opts.Action == "uninstall" {
			code, err = runUninstall(opts, w.installRoot, w.dataRoot)
		} else {
			code, err = runInstall(opts, w.installRoot, w.dataRoot)
		}
		w.mu.Lock()
		w.code = code
		w.err = err
		w.mu.Unlock()
		procPostMessage.Call(w.hwnd, wmDone, 0, 0)
	}(w.opts)
}

func (w *setupWizard) finish() {
	w.running = false
	w.done = true
	w.enableInputs(false)
	w.show(w.progress, false)
	w.show(w.cancel, false)
	w.show(w.openTerm, w.opts.Action != "uninstall")
	setText(w.primary, "Finish")
	procEnableWindow.Call(w.primary, 1)
	w.mu.Lock()
	code, resultErr := w.code, w.err
	w.mu.Unlock()
	if resultErr != nil {
		setText(w.heading, "Setup could not finish")
		message := fmt.Sprintf("%v", resultErr)
		if code == retryRequiredCode {
			message += "\r\n\r\nClose running DefenseClaw terminals and run setup again."
		}
		setText(w.description, message)
		w.show(w.openTerm, false)
		return
	}
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
		setText(w.description, "Next, open a terminal and run defenseclaw init to configure connectors, then run defenseclaw tui to review activity. This installer installed the existing CLI/TUI, gateway, hook launcher, and managed runtime; it is not a separate DefenseClaw GUI application.")
	}
}

func (w *setupWizard) enableInputs(enabled bool) {
	for _, hwnd := range []uintptr{w.pathEdit, w.connector, w.mode, w.start, w.deleteData, w.primary, w.cancel} {
		procEnableWindow.Call(hwnd, boolToUintptr(enabled))
	}
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
	powerShell, err := systemPowerShellPath()
	if err != nil {
		messageBox(w.hwnd, "Setup could not locate the system PowerShell. Open a terminal and run defenseclaw init, then defenseclaw tui.", "DefenseClaw Setup", 0x30)
		return
	}
	verb := windows.StringToUTF16Ptr("open")
	file := windows.StringToUTF16Ptr(powerShell)
	params := windows.StringToUTF16Ptr("-NoExit")
	dir := windows.StringToUTF16Ptr(commandDir)
	ret, _, _ := procShellExecute.Call(w.hwnd, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(dir)), swShowNormal)
	runtime.KeepAlive(verb)
	runtime.KeepAlive(file)
	runtime.KeepAlive(params)
	runtime.KeepAlive(dir)
	if ret <= 32 {
		messageBox(w.hwnd, "Setup could not open PowerShell. Open a terminal and run defenseclaw init, then defenseclaw tui.", "DefenseClaw Setup", 0x30)
	}
}

func systemPowerShellPath() (string, error) {
	buffer := make([]uint16, windows.MAX_PATH)
	ret, _, err := procGetSystemDirectory.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if ret == 0 || int(ret) > len(buffer) {
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

func messageBox(hwnd uintptr, text, title string, flags uintptr) {
	procMessageBox.Call(hwnd, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(title))), flags)
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
