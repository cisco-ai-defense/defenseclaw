// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const WindowsManagedSIDUnregisteredReason = "enterprise_managed_sid_unregistered"

// ErrWindowsManagedSIDUnregistered is wrapped only by resolver failures whose
// cause is that the current SID is absent from the protected target set.
// Classify with errors.Is, never by message text: other errors can carry
// target-owned paths.
var ErrWindowsManagedSIDUnregistered = errors.New(WindowsManagedSIDUnregisteredReason)

// WindowsManagedRuntimeDriftReason is the hook failure reason of runtime
// state that drifted without any integrity finding.
const WindowsManagedRuntimeDriftReason = "enterprise_managed_runtime_drift"

// Resolver failure classes. A drift failure (permission or owner drift on the
// user's runtime files, an oversized file, a stale selector or generation, a
// short-path invocation of the policy executable, a Cursor adapter mode that
// differs from the generation, a busy lock) follows the hook's configured
// fail mode. A boundary failure (a reparse point, a hard link, a wrong object
// type, a hook executable or machine file an untrusted principal can write,
// an invalid identity, content that fails its protected digest) stays closed.
// Classify with WindowsManagedRuntimeFailureClassOf, never by message text.
var (
	ErrWindowsManagedRuntimeDrift    = errors.New(WindowsManagedRuntimeDriftReason)
	ErrWindowsManagedRuntimeBoundary = errors.New("enterprise_managed_runtime_boundary")
)

// WindowsManagedRuntimeFailureClass is the class of a resolver failure.
type WindowsManagedRuntimeFailureClass string

const (
	WindowsManagedRuntimeFailureNone         WindowsManagedRuntimeFailureClass = ""
	WindowsManagedRuntimeFailureUnregistered WindowsManagedRuntimeFailureClass = "unregistered"
	WindowsManagedRuntimeFailureDrift        WindowsManagedRuntimeFailureClass = "drift"
	WindowsManagedRuntimeFailureBoundary     WindowsManagedRuntimeFailureClass = "boundary"
)

// WindowsManagedRuntimeFailureClassOf classifies a resolver error. A boundary
// tag wins over every other class, and an untagged error is a boundary.
func WindowsManagedRuntimeFailureClassOf(err error) WindowsManagedRuntimeFailureClass {
	switch {
	case err == nil:
		return WindowsManagedRuntimeFailureNone
	case errors.Is(err, ErrWindowsManagedRuntimeBoundary):
		return WindowsManagedRuntimeFailureBoundary
	case errors.Is(err, ErrWindowsManagedSIDUnregistered):
		return WindowsManagedRuntimeFailureUnregistered
	case errors.Is(err, ErrWindowsManagedRuntimeDrift):
		return WindowsManagedRuntimeFailureDrift
	}
	return WindowsManagedRuntimeFailureBoundary
}

// windowsManagedRuntimeDriftError tags err as drift unless it already
// carries a class; an existing boundary tag is never downgraded.
func windowsManagedRuntimeDriftError(err error) error {
	if errors.Is(err, ErrWindowsManagedRuntimeBoundary) ||
		errors.Is(err, ErrWindowsManagedRuntimeDrift) ||
		errors.Is(err, ErrWindowsManagedSIDUnregistered) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrWindowsManagedRuntimeDrift, err)
}

func windowsManagedRuntimeBoundaryError(err error) error {
	if errors.Is(err, ErrWindowsManagedRuntimeBoundary) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrWindowsManagedRuntimeBoundary, err)
}

// classifyWindowsManagedHookRuntimeError tags an error that no resolver step
// classified. Only typed evidence makes it drift: a busy or denied handle, a
// lock or read deadline, a selector that kept changing. Everything else is a
// boundary.
func classifyWindowsManagedHookRuntimeError(err error) error {
	if err == nil ||
		errors.Is(err, ErrWindowsManagedRuntimeBoundary) ||
		errors.Is(err, ErrWindowsManagedRuntimeDrift) ||
		errors.Is(err, ErrWindowsManagedSIDUnregistered) {
		return err
	}
	if errors.Is(err, errWindowsManagedHardlink) {
		return windowsManagedRuntimeBoundaryError(err)
	}
	if windowsManagedRuntimeDriftEvidence(err) {
		return windowsManagedRuntimeDriftError(err)
	}
	return windowsManagedRuntimeBoundaryError(err)
}

func windowsManagedRuntimeDriftEvidence(err error) bool {
	return errors.Is(err, ErrWindowsManagedRuntimeGenerationConflict) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.Errno(windows.WAIT_TIMEOUT)) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, context.DeadlineExceeded)
}

// stricterWindowsManagedFailMode combines configured fail modes: closed when
// any is closed, open when the rest agree on open, empty when none is known.
func stricterWindowsManagedFailMode(modes ...string) string {
	result := ""
	for _, mode := range modes {
		switch mode {
		case "closed":
			return "closed"
		case "open":
			result = "open"
		}
	}
	return result
}

// WindowsManagedHookRuntime is the administrator-authorized runtime selected
// for the current process token. PolicyActive distinguishes a clean
// post-uninstall absence from a damaged or unregistered active global policy.
type WindowsManagedHookRuntime struct {
	Connector          string `json:"connector"`
	DataDir            string `json:"data_dir"`
	PolicyActive       bool   `json:"policy_active"`
	Registered         bool   `json:"registered"`
	GatewayAddr        string `json:"gateway_addr"`
	GatewayServiceName string `json:"gateway_service_name"`
	FailMode           string `json:"fail_mode"`
	ScopedToken        string `json:"-"`
	GenerationID       string `json:"generation_id"`
}

// String deliberately omits ScopedToken so diagnostic formatting cannot
// disclose the per-target gateway credential.
func (r WindowsManagedHookRuntime) String() string {
	return fmt.Sprintf(
		"WindowsManagedHookRuntime{Connector:%q DataDir:%q PolicyActive:%t Registered:%t GatewayAddr:%q GatewayServiceName:%q GenerationID:%q}",
		r.Connector,
		r.DataDir,
		r.PolicyActive,
		r.Registered,
		r.GatewayAddr,
		r.GatewayServiceName,
		r.GenerationID,
	)
}

func (r WindowsManagedHookRuntime) GoString() string { return r.String() }

// ResolveWindowsManagedHookRuntime performs connector-aware machine-policy
// resolution before any target-owned configuration is trusted.
//
// Every failure carries a class (WindowsManagedRuntimeFailureClassOf). On a
// drift failure FailMode is the configured fail mode recovered from
// authenticated state, or empty when none could be established; on every
// other failure it is empty.
func ResolveWindowsManagedHookRuntime(
	hookExecutable string,
	connectorName string,
) (WindowsManagedHookRuntime, error) {
	var (
		runtime WindowsManagedHookRuntime
		err     error
	)
	name := strings.ToLower(strings.TrimSpace(connectorName))
	switch name {
	case "claudecode":
		runtime, err = resolveWindowsClaudeManagedHookRuntime(hookExecutable)
	case "codex":
		runtime, err = resolveWindowsCodexManagedHookRuntime(hookExecutable)
	case "cursor":
		runtime, err = resolveWindowsCursorManagedHookRuntime(hookExecutable)
	default:
		return WindowsManagedHookRuntime{}, windowsManagedRuntimeBoundaryError(fmt.Errorf(
			"enterprise hooks: unsupported Windows managed connector %q",
			connectorName,
		))
	}
	if err == nil {
		return runtime, nil
	}
	err = classifyWindowsManagedHookRuntimeError(err)
	if WindowsManagedRuntimeFailureClassOf(err) != WindowsManagedRuntimeFailureDrift {
		runtime.FailMode = ""
	}
	return runtime, err
}

// windowsManagedHookLongPath expands a short (8.3) path to its long form. It
// is a seam for tests.
var windowsManagedHookLongPath = windowsLongPathName

func windowsLongPathName(path string) (string, bool) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", false
	}
	size, err := windows.GetLongPathName(pointer, nil, 0)
	if err != nil || size == 0 {
		return "", false
	}
	buffer := make([]uint16, size)
	written, err := windows.GetLongPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || written == 0 || written >= uint32(len(buffer)) {
		return "", false
	}
	return windows.UTF16ToString(buffer[:written]), true
}

// windowsManagedHookExecutableMismatch classifies an invoking executable that
// differs from the policy executable. When both name the same file once short
// (8.3) components are expanded, only the invocation path drifted; any other
// executable is a boundary.
func windowsManagedHookExecutableMismatch(
	result *WindowsManagedHookRuntime,
	connectorName string,
	targetSID *windows.SID,
	policyFailMode string,
	invoked string,
	policy string,
) error {
	err := fmt.Errorf(
		"enterprise hooks: invoking hook executable %s does not match active %s policy executable %s",
		invoked,
		connectorName,
		policy,
	)
	longInvoked, invokedOK := windowsManagedHookLongPath(invoked)
	longPolicy, policyOK := windowsManagedHookLongPath(policy)
	if !invokedOK || !policyOK || !sameWindowsEnterprisePath(longInvoked, longPolicy) {
		return windowsManagedRuntimeBoundaryError(err)
	}
	result.FailMode = windowsManagedRuntimeTrustedFailMode(connectorName, targetSID, policyFailMode)
	return windowsManagedRuntimeDriftError(err)
}

// classifyWindowsManagedRuntimeGenerationFailure classifies a generation
// resolver failure. The generation resolver reports untyped errors, so the
// hook re-examines the integrity boundary itself: identity, the hook
// executable, the machine selector and the object types of the user's runtime
// files. Any finding there keeps the failure closed. Without one the failure
// is drift (permissions, owner, size, a stale selector or generation) and
// takes the configured fail mode recovered from authenticated state.
func classifyWindowsManagedRuntimeGenerationFailure(
	result *WindowsManagedHookRuntime,
	opts WindowsManagedRuntimeGenerationResolveOptions,
	policyFailMode string,
	err error,
) error {
	if errors.Is(err, ErrWindowsManagedSIDUnregistered) ||
		errors.Is(err, ErrWindowsManagedRuntimeBoundary) {
		return err
	}
	if errors.Is(err, errWindowsManagedHardlink) {
		return windowsManagedRuntimeBoundaryError(err)
	}
	if finding := windowsManagedRuntimeBoundaryProbe(opts); finding != nil {
		return windowsManagedRuntimeBoundaryError(errors.Join(err, finding))
	}
	target, _ := windows.StringToSid(opts.TargetSID)
	result.FailMode = windowsManagedRuntimeTrustedFailMode(opts.Connector, target, policyFailMode)
	return windowsManagedRuntimeDriftError(err)
}

// windowsManagedRuntimeBoundaryProbe is a seam for tests.
var windowsManagedRuntimeBoundaryProbe = probeWindowsManagedRuntimeBoundary

// probeWindowsManagedRuntimeBoundary returns the first integrity finding on
// the hook's resolution path, or nil when only drift remains. It reports
// positive evidence only: a check that cannot run (a denied handle, a missing
// bundle) is not a finding.
func probeWindowsManagedRuntimeBoundary(opts WindowsManagedRuntimeGenerationResolveOptions) error {
	opts, target, err := validateWindowsManagedRuntimeGenerationResolveOptions(opts)
	if err != nil {
		return err
	}
	if err := requireWindowsManagedRuntimeProcessTarget(target); err != nil {
		return err
	}
	if err := windowsEnterpriseHookTrustCheck(opts.HookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: managed hook executable trust check failed: %w", err)
	}
	selectorPath, err := windowsManagedRuntimeSelectorPath(opts.Connector)
	if err != nil {
		return err
	}
	if err := windowsManagedRuntimeObjectTypeFinding(selectorPath, false, true); err != nil {
		return err
	}
	if _, statErr := os.Lstat(selectorPath); statErr == nil {
		if err := windowsManagedPolicyFileTrustCheck(selectorPath); err != nil {
			return fmt.Errorf("enterprise hooks: managed runtime selector is writable by an untrusted principal: %w", err)
		}
	}
	for _, directory := range []string{opts.DataDir, filepath.Join(opts.DataDir, "hooks")} {
		if err := windowsManagedRuntimeObjectTypeFinding(directory, true, false); err != nil {
			return err
		}
	}
	selector, _, exists, err := readWindowsManagedRuntimeSelector(opts.Connector, true)
	if err != nil || !exists {
		return nil
	}
	entry, ok := windowsManagedRuntimeSelectorTargetForSID(selector, opts.TargetSID)
	if !ok {
		return nil
	}
	bundlePath, err := windowsManagedRuntimeBundlePath(entry.DataDir, entry.Connector, entry.GenerationID)
	if err != nil {
		return err
	}
	if err := windowsManagedRuntimeObjectTypeFinding(bundlePath, false, true); err != nil {
		return err
	}
	if _, err := readWindowsManagedRuntimeAuthenticatedBundle(entry, bundlePath); errors.Is(err, errWindowsManagedRuntimeBundleForged) {
		return err
	}
	return nil
}

// windowsManagedRuntimeObjectTypeFinding reports a reparse point on path or
// any ancestor, a wrong object type, or a regular file with more than one
// link. A missing directory is a finding (the runtime home is gone); a
// missing file is not when allowMissing is set.
func windowsManagedRuntimeObjectTypeFinding(path string, wantDir, allowMissing bool) error {
	if err := windowsManagedRuntimeReparseFinding(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if allowMissing {
			return nil
		}
		return fmt.Errorf("enterprise hooks: managed runtime directory is missing: %s", path)
	}
	if err != nil {
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: managed runtime path is a link: %s", path)
	}
	if wantDir {
		if !info.IsDir() {
			return fmt.Errorf("enterprise hooks: expected directory: %s", path)
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("enterprise hooks: expected regular file: %s", path)
	}
	if err := validateWindowsRegularFileSingleLink(path); errors.Is(err, errWindowsManagedHardlink) {
		return err
	}
	return nil
}

func windowsManagedRuntimeReparseFinding(path string) error {
	current, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		pointer, err := winpath.UTF16Ptr(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 &&
			!windowsPathHasHarmlessReparseTag(current) {
			return fmt.Errorf("enterprise hooks: reparse point in path: %s", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

// errWindowsManagedRuntimeBundleForged marks bundle bytes that do not match
// the digest the machine-protected selector pins.
var errWindowsManagedRuntimeBundleForged = errors.New(
	"enterprise hooks: managed runtime bundle does not match its protected digest",
)

// readWindowsManagedRuntimeAuthenticatedBundle reads one selected bundle and
// authenticates it by the selector's digest alone, without the user-path
// ACL checks a drifted runtime fails.
func readWindowsManagedRuntimeAuthenticatedBundle(
	entry windowsManagedRuntimeSelectorTarget,
	path string,
) (windowsManagedRuntimeBundle, error) {
	data, err := connector.ReadManagedHookRuntimeFile(
		path,
		"immutable managed runtime generation",
		windowsManagedRuntimeBundleMaxBytes,
	)
	if err != nil {
		return windowsManagedRuntimeBundle{}, err
	}
	if windowsManagedRuntimeSHA256(data) != entry.BundleSHA256 {
		return windowsManagedRuntimeBundle{}, errWindowsManagedRuntimeBundleForged
	}
	bundle, err := decodeWindowsManagedRuntimeBundle(data)
	if err != nil {
		return windowsManagedRuntimeBundle{}, err
	}
	if bundle.GenerationID != entry.GenerationID ||
		bundle.Connector != entry.Connector ||
		!strings.EqualFold(bundle.TargetSID, entry.SID) {
		return windowsManagedRuntimeBundle{}, errors.New(
			"enterprise hooks: managed runtime bundle does not match its selector entry",
		)
	}
	return bundle, nil
}

// windowsManagedRuntimeTrustedFailMode recovers the configured fail mode of
// a drifted runtime from authenticated state only: the machine policy's own
// mode when it has one, and the selected generation's mode when its bytes
// still match the protected digest. The stricter mode wins; an empty result
// means no configured mode could be established, which the hook treats as
// closed.
func windowsManagedRuntimeTrustedFailMode(
	connectorName string,
	target *windows.SID,
	policyFailMode string,
) string {
	return stricterWindowsManagedFailMode(
		policyFailMode,
		windowsManagedRuntimeGenerationFailMode(connectorName, target),
	)
}

// windowsManagedRuntimeGenerationFailMode is a seam for tests.
var windowsManagedRuntimeGenerationFailMode = readWindowsManagedRuntimeGenerationFailMode

func readWindowsManagedRuntimeGenerationFailMode(connectorName string, target *windows.SID) string {
	if target == nil {
		return ""
	}
	selector, _, exists, err := readWindowsManagedRuntimeSelector(connectorName, true)
	if err != nil || !exists {
		return ""
	}
	entry, ok := windowsManagedRuntimeSelectorTargetForSID(selector, target.String())
	if !ok {
		return ""
	}
	path, err := windowsManagedRuntimeBundlePath(entry.DataDir, entry.Connector, entry.GenerationID)
	if err != nil {
		return ""
	}
	bundle, err := readWindowsManagedRuntimeAuthenticatedBundle(entry, path)
	if err != nil {
		return ""
	}
	return bundle.FailMode
}

func windowsCurrentProcessSID() *windows.SID {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil
	}
	return user.User.Sid
}

func resolveWindowsCursorManagedHookRuntime(
	hookExecutable string,
) (WindowsManagedHookRuntime, error) {
	target, err := resolveWindowsCursorManagedPolicyTarget()
	result := WindowsManagedHookRuntime{
		Connector: "cursor",
		DataDir:   target.dataDir,
	}
	if err != nil {
		return result, err
	}
	if !target.active {
		return result, nil
	}
	result.PolicyActive = true
	if !sameWindowsEnterprisePath(target.hookExecutable, hookExecutable) {
		return result, windowsManagedHookExecutableMismatch(
			&result,
			"cursor",
			target.targetSID,
			target.hookFailMode,
			hookExecutable,
			target.hookExecutable,
		)
	}
	if !target.registered {
		sid := "<unknown>"
		if target.targetSID != nil {
			sid = target.targetSID.String()
		}
		return result, fmt.Errorf(
			"%w: connector cursor current SID %s is absent from the protected target set",
			ErrWindowsManagedSIDUnregistered,
			sid,
		)
	}
	cursorResolve := WindowsManagedRuntimeGenerationResolveOptions{
		Connector:               "cursor",
		TargetSID:               target.targetSID.String(),
		DataDir:                 target.dataDir,
		HookExecutable:          hookExecutable,
		MachinePolicyRegistered: true,
	}
	generation, err := windowsManagedRuntimeGenerationResolve(cursorResolve)
	if err != nil {
		return result, classifyWindowsManagedRuntimeGenerationFailure(
			&result,
			cursorResolve,
			target.hookFailMode,
			err,
		)
	}
	result.GatewayAddr = generation.GatewayAddr
	if err := verifyWindowsCursorRuntimeDeliveryMode(target.hookFailMode, generation.FailMode); err != nil {
		// Both modes are authenticated: the adapter's by the machine policy,
		// the generation's by its protected digest. Reconciliation brings them
		// back together; until then the stricter one decides.
		result.FailMode = stricterWindowsManagedFailMode(target.hookFailMode, generation.FailMode)
		return result, windowsManagedRuntimeDriftError(err)
	}
	result.GatewayServiceName = generation.GatewayServiceName
	result.ScopedToken = generation.ScopedToken()
	result.GenerationID = generation.GenerationID
	result.FailMode = generation.FailMode
	result.Registered = true
	return result, nil
}

func verifyWindowsCursorRuntimeDeliveryMode(adapterMode, generationMode string) error {
	// Legacy singleton adapters had no per-SID mode binding. Reconciliation
	// migrates them without invalidating previously authenticated generations.
	if adapterMode != "" && adapterMode != generationMode {
		return errors.New("enterprise hooks: Cursor adapter mode differs from the authenticated runtime generation")
	}
	return nil
}

func validateWindowsCursorManagedRuntime(
	target windowsCursorManagedPolicyTarget,
) error {
	if target.targetSID == nil {
		return errors.New("enterprise hooks: Cursor managed runtime target SID is required")
	}
	if err := windowsEnterpriseHookTrustCheck(target.hookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: Cursor managed hook executable trust check failed: %w", err)
	}
	hookDir := filepath.Join(target.dataDir, "hooks")
	tokenPath, err := connector.HookTokenFilePath(hookDir, "cursor")
	if err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		dir  bool
	}{
		{target.dataDir, true},
		{hookDir, true},
		{filepath.Join(hookDir, ".hookcfg"), false},
		{filepath.Join(hookDir, ".hookcfg.lock"), false},
		{filepath.Join(hookDir, ".hookcfg.cursor"), false},
		{tokenPath, false},
		{filepath.Join(target.dataDir, "hook_contract_lock.json"), false},
		{filepath.Join(target.dataDir, "hook_contract_lock.json.lock"), false},
	} {
		if err := validateWindowsUserPathElement(
			item.path,
			target.targetSID,
			item.dir,
			item.dir,
			true,
		); err != nil {
			return fmt.Errorf("enterprise hooks: Cursor managed runtime trust check failed for %s: %w", item.path, err)
		}
		if !item.dir {
			info, err := os.Lstat(item.path)
			if err != nil {
				return err
			}
			if info.Size() > windowsEnterpriseUserFileMaxBytes {
				return fmt.Errorf("enterprise hooks: Cursor runtime file exceeds the bounded size: %s", item.path)
			}
		}
	}
	if err := connector.ValidateManagedNativeHookRuntime(
		target.dataDir,
		target.gatewayAddr,
		"cursor",
	); err != nil {
		return fmt.Errorf("enterprise hooks: Cursor managed runtime sidecars are invalid: %w", err)
	}
	cursorPaths, err := windowsCursorManagedPaths()
	if err != nil {
		return err
	}
	hooksPath := cursorPaths.Hooks
	adapterPath := cursorPaths.Adapter
	lock, err := connector.LoadHookContractLockEntryForMode(target.dataDir, "cursor", true)
	if err != nil {
		return fmt.Errorf("enterprise hooks: load Cursor managed hook contract: %w", err)
	}
	if err := connector.ValidateWindowsManagedHookContractGatewayServiceBinding(lock); err != nil {
		return fmt.Errorf("enterprise hooks: Cursor managed gateway binding: %w", err)
	}
	if lock.Connector != "cursor" ||
		len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], hooksPath) ||
		len(lock.Locations.HookScriptPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookScriptPaths[0], adapterPath) ||
		(lock.HookFailMode != "open" && lock.HookFailMode != "closed") {
		return errors.New("enterprise hooks: Cursor managed hook contract does not identify the active enterprise adapter")
	}
	return nil
}

func resolveWindowsClaudeManagedHookRuntime(
	hookExecutable string,
) (WindowsManagedHookRuntime, error) {
	target, err := resolveWindowsClaudeManagedPolicyTarget()
	result := WindowsManagedHookRuntime{
		Connector: "claudecode",
		DataDir:   target.dataDir,
	}
	if err != nil {
		return result, err
	}
	if !target.policyExists {
		return result, nil
	}
	result.PolicyActive = true
	gatewayAddr, gatewayErr := connector.NormalizeWindowsManagedGatewayAddr(target.gatewayAddr)
	if gatewayErr != nil || gatewayAddr != target.gatewayAddr {
		return result, windowsManagedRuntimeBoundaryError(
			errors.New("enterprise hooks: active Claude policy has no valid protected gateway address"),
		)
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(target.gatewayServiceName); err != nil {
		return result, windowsManagedRuntimeBoundaryError(err)
	}
	if !sameWindowsEnterprisePath(target.hookExecutable, hookExecutable) {
		return result, windowsManagedHookExecutableMismatch(
			&result,
			"claudecode",
			target.targetSID,
			"",
			hookExecutable,
			target.hookExecutable,
		)
	}
	if !target.registered {
		sid := "<unknown>"
		if target.targetSID != nil {
			sid = target.targetSID.String()
		}
		return result, fmt.Errorf(
			"%w: connector claudecode current SID %s is absent from the protected target set",
			ErrWindowsManagedSIDUnregistered,
			sid,
		)
	}
	claudeResolve := WindowsManagedRuntimeGenerationResolveOptions{
		Connector:               "claudecode",
		TargetSID:               target.targetSID.String(),
		DataDir:                 target.dataDir,
		HookExecutable:          hookExecutable,
		MachinePolicyRegistered: true,
	}
	generation, err := windowsManagedRuntimeGenerationResolve(claudeResolve)
	if err != nil {
		return result, classifyWindowsManagedRuntimeGenerationFailure(&result, claudeResolve, "", err)
	}
	// The hook consumes the generation gateway identity, not the
	// policy record. Reject a policy whose gateway metadata does not
	// match the resolved generation instead of silently trusting one
	// source. The generation resolver otherwise never compares them.
	// Both records are protected, so a mismatch is a stale generation
	// awaiting reconciliation: drift under the generation's own mode.
	if generation.GatewayAddr != target.gatewayAddr ||
		generation.GatewayServiceName != target.gatewayServiceName {
		result.FailMode = stricterWindowsManagedFailMode(generation.FailMode)
		return result, windowsManagedRuntimeDriftError(errors.New(
			"enterprise hooks: Claude managed policy gateway identity does not match the resolved generation",
		))
	}
	result.GatewayAddr = generation.GatewayAddr
	result.GatewayServiceName = generation.GatewayServiceName
	result.ScopedToken = generation.ScopedToken()
	result.GenerationID = generation.GenerationID
	result.FailMode = generation.FailMode
	result.Registered = true
	return result, nil
}

func resolveWindowsCodexManagedHookRuntime(
	hookExecutable string,
) (WindowsManagedHookRuntime, error) {
	result := WindowsManagedHookRuntime{
		Connector: "codex",
	}
	registry, err := connector.ResolveWindowsCodexManagedRuntimeRegistry(hookExecutable)
	if err != nil {
		result.PolicyActive = true
		err = fmt.Errorf("enterprise hooks: resolve protected Codex runtime state: %w", err)
		// The registry compares the invoking executable itself. When the
		// long form of an 8.3 invocation resolves, the only difference is
		// the invocation path.
		if longPath, ok := windowsManagedHookLongPath(hookExecutable); ok &&
			!sameWindowsEnterprisePath(longPath, hookExecutable) {
			if _, longErr := connector.ResolveWindowsCodexManagedRuntimeRegistry(longPath); longErr == nil {
				result.FailMode = windowsManagedRuntimeTrustedFailMode("codex", windowsCurrentProcessSID(), "")
				return result, windowsManagedRuntimeDriftError(err)
			}
		}
		return result, err
	}
	if !registry.Active {
		return result, nil
	}
	result.PolicyActive = true
	targets := registry.Targets
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return result, windowsManagedRuntimeBoundaryError(
			fmt.Errorf("enterprise hooks: resolve current Windows hook SID: %w", err),
		)
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return result, windowsManagedRuntimeBoundaryError(
			errors.New("enterprise hooks: current Windows hook token has no user SID"),
		)
	}
	currentSID := tokenUser.User.Sid
	var selected *connector.WindowsCodexManagedRuntimeTarget
	for index := range targets {
		if strings.EqualFold(targets[index].SID, currentSID.String()) {
			selected = &targets[index]
			break
		}
	}
	if selected == nil {
		return result, fmt.Errorf(
			"%w: connector codex current SID %s is absent from the protected target set",
			ErrWindowsManagedSIDUnregistered,
			currentSID,
		)
	}
	result.DataDir = selected.DataDir
	codexResolve := WindowsManagedRuntimeGenerationResolveOptions{
		Connector:               "codex",
		TargetSID:               currentSID.String(),
		DataDir:                 selected.DataDir,
		HookExecutable:          hookExecutable,
		MachinePolicyRegistered: true,
	}
	generation, err := windowsManagedRuntimeGenerationResolve(codexResolve)
	if err != nil {
		return result, classifyWindowsManagedRuntimeGenerationFailure(&result, codexResolve, "", err)
	}
	result.GatewayAddr = generation.GatewayAddr
	result.GatewayServiceName = generation.GatewayServiceName
	result.ScopedToken = generation.ScopedToken()
	result.GenerationID = generation.GenerationID
	result.FailMode = generation.FailMode
	result.Registered = true
	return result, nil
}

func validateWindowsCodexManagedRuntime(
	dataDir string,
	targetSID *windows.SID,
	hookExecutable string,
) error {
	if targetSID == nil {
		return errors.New("enterprise hooks: Codex managed runtime target SID is required")
	}
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: Codex managed hook executable trust check failed: %w", err)
	}
	if !strings.EqualFold(filepath.Base(dataDir), ".defenseclaw") {
		return fmt.Errorf("enterprise hooks: Codex managed data directory is noncanonical: %s", dataDir)
	}
	home := filepath.Dir(dataDir)
	validatedHome, validatedSID, err := validateWindowsEnterpriseHome(home, targetSID.String())
	if err != nil {
		return err
	}
	if !sameWindowsEnterprisePath(validatedHome, home) ||
		!validatedSID.Equals(targetSID) {
		return errors.New("enterprise hooks: Codex managed runtime identity changed during validation")
	}
	hookDir := filepath.Join(dataDir, "hooks")
	tokenPath, err := connector.HookTokenFilePath(hookDir, "codex")
	if err != nil {
		return err
	}
	requirementsPath, err := windowsCodexMachineRequirementsPath()
	if err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		dir  bool
	}{
		{dataDir, true},
		{hookDir, true},
		{filepath.Join(hookDir, ".hookcfg"), false},
		{filepath.Join(hookDir, ".hookcfg.lock"), false},
		{filepath.Join(hookDir, ".hookcfg.codex"), false},
		{tokenPath, false},
		{filepath.Join(dataDir, "hook_contract_lock.json"), false},
		{filepath.Join(dataDir, "hook_contract_lock.json.lock"), false},
	} {
		if err := validateWindowsUserPathElement(
			item.path,
			targetSID,
			item.dir,
			item.dir,
			true,
		); err != nil {
			return fmt.Errorf(
				"enterprise hooks: Codex managed runtime trust check failed for %s: %w",
				item.path,
				err,
			)
		}
		if !item.dir {
			info, err := os.Lstat(item.path)
			if err != nil {
				return fmt.Errorf("enterprise hooks: inspect Codex managed runtime %s: %w", item.path, err)
			}
			if info.Size() > windowsEnterpriseUserFileMaxBytes {
				return fmt.Errorf(
					"enterprise hooks: Codex managed runtime %s exceeds %d-byte limit",
					item.path,
					windowsEnterpriseUserFileMaxBytes,
				)
			}
		}
	}
	lock, err := connector.LoadHookContractLockEntryForMode(
		dataDir,
		"codex",
		true,
	)
	if err != nil {
		return fmt.Errorf(
			"enterprise hooks: load Codex managed hook contract: %w",
			err,
		)
	}
	if err := connector.ValidateWindowsManagedHookContractGatewayServiceBinding(lock); err != nil {
		return fmt.Errorf("enterprise hooks: Codex managed gateway binding: %w", err)
	}
	if lock.Connector != "codex" ||
		len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], requirementsPath) ||
		len(lock.Locations.HookScriptPaths) != 0 ||
		(lock.HookFailMode != "open" && lock.HookFailMode != "closed") {
		return errors.New("enterprise hooks: Codex managed hook contract lock does not identify the active machine requirements")
	}
	if err := connector.ValidateManagedHookRuntimeState(dataDir, "codex", lock.HookFailMode); err != nil {
		return fmt.Errorf("enterprise hooks: Codex managed runtime sidecars are invalid: %w", err)
	}
	return nil
}

func windowsCodexMachineRequirementsPath() (string, error) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve trusted ProgramData: %w", err)
	}
	return filepath.Join(programData, "OpenAI", "Codex", "requirements.toml"), nil
}
