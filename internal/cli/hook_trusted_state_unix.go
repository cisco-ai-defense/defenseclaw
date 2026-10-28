// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The standalone managed hook runtime on Linux and macOS.
//
// The administrator-owned hook binary (/opt/defenseclaw/bin/defenseclaw-hook
// or /opt/cisco/defenseclaw/bin/defenseclaw-hook) runs as the agent's user.
// Everything security-relevant it needs comes from the root-owned runtime
// descriptor the lifecycle writes — never from the user's environment,
// flags or files: the gateway address, the hook socket and the gateway
// service uid the listener must run as.
//
// A hook invoked with --enterprise-managed fails closed when its descriptor
// is missing, even if vendor machine policy has already been removed. Agent
// sessions may retain a hook registration through uninstall or rollback.
// Stop and session-end events keep their neutral allow to avoid agent loops.
// A descriptor that fails its trust checks also fails closed.
//
// The hook socket is the only transport. A descriptor that names no hook
// socket also fails closed: there is no loopback TCP fallback, because
// another local user can hold that port while the gateway restarts.

const (
	standaloneRuntimeReasonInvalid           = "enterprise_managed_runtime_state_invalid"
	standaloneRuntimeReasonDescriptorMissing = "enterprise_managed_runtime_descriptor_missing"
	standaloneRuntimeReasonHookSocketMissing = "enterprise_managed_hook_socket_missing"
)

// The hook inherits the agent's process context. A managed Linux hook refuses
// a private user namespace, where it can not verify the gateway's listener,
// and a traced process. A private mount view is not refused on its own (a
// pam_namespace login has one). The hook does no policy-view work: the
// gateway proves the published vendor policy when it changes and alerts off
// the call path (gateway/managed_policy_view.go). This is an invocation
// check: an agent that never loads its managed hook still has no invocation
// to check, which status reports separately.
var standaloneLinuxHookContext = func() string {
	return linuxManagedHookContextReason(os.Readlink, openLinuxHookContextFile)
}

func openLinuxHookContextFile(path string) (io.ReadCloser, error) { return os.Open(path) }

// linuxHookContextMaxBytes bounds every proc read so a replaced proc file
// cannot consume unbounded memory. In the host user namespace uid_map is one
// line. Only the head of status is read: TracerPid is its eighth line, while
// later lines such as Groups grow with the account (up to 65,536
// supplementary groups), and a large file must not refuse a valid call.
const linuxHookContextMaxBytes = 16 * 1024

func linuxManagedHookContextReason(readlink func(string) (string, error), open func(string) (io.ReadCloser, error)) string {
	uidMap, err := readLinuxHookContextFile(open, "/proc/self/uid_map")
	if err != nil {
		return hookexec.ManagedProcessContextUnknownReason
	}
	fields := strings.Fields(string(uidMap))
	if len(fields) != 3 || fields[0] != "0" || fields[1] != "0" || fields[2] != "4294967295" {
		return hookexec.ManagedUserNamespaceReason
	}
	self, err := readlink("/proc/self/ns/user")
	if err != nil || self == "" {
		return hookexec.ManagedProcessContextUnknownReason
	}
	// SELinux on managed RHEL denies standard users readlink on /proc/1/ns,
	// even in the host namespaces. An unprivileged private user namespace
	// can not keep the full host uid map checked above, so that check
	// stands alone then.
	if host, err := readlink("/proc/1/ns/user"); err == nil && host != "" && host != self {
		return hookexec.ManagedUserNamespaceReason
	}
	return linuxTracerPidReason(open)
}

func readLinuxHookContextFile(open func(string) (io.ReadCloser, error), path string) ([]byte, error) {
	f, err := open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, linuxHookContextMaxBytes+1))
	if err != nil || len(data) > linuxHookContextMaxBytes {
		return nil, errors.New("cannot read bounded Linux process context")
	}
	return data, nil
}

// linuxTracerPidReason reads /proc/self/status only up to its first complete
// TracerPid line. A status with no complete TracerPid line in its first
// linuxHookContextMaxBytes, or an unparsable one, is unverifiable.
func linuxTracerPidReason(open func(string) (io.ReadCloser, error)) string {
	f, err := open("/proc/self/status")
	if err != nil {
		return hookexec.ManagedProcessContextUnknownReason
	}
	defer f.Close()
	// Keep read-ahead smaller than the Uid/Gid/FDSize lines between
	// TracerPid and Groups in the kernel's status format. A default-sized
	// bufio reader asks proc for 4 KiB at once, making a valid hook wait
	// for (or fail on) the account's entire Groups line before it can see
	// TracerPid, even though the parser stops there.
	head := bufio.NewReaderSize(io.LimitReader(f, linuxHookContextMaxBytes), 16)
	for {
		line, err := head.ReadString('\n')
		if err != nil {
			// EOF or the bound before a complete TracerPid line: a cut
			// line is never trusted.
			return hookexec.ManagedProcessContextUnknownReason
		}
		value, ok := strings.CutPrefix(line, "TracerPid:")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || pid < 0 {
			return hookexec.ManagedProcessContextUnknownReason
		}
		if pid != 0 {
			return hookexec.ManagedTracedProcessReason
		}
		return ""
	}
}

// reportStandaloneHookRefusal tells the gateway, over the hook socket, that
// this hook refused its agent, so the refusal is in the audit log and the
// gateway log as a refused unenrolled account is (GAP-0923). From a private
// user namespace the listener's owner cannot be checked (it reads as the
// overflow uid), so the report carries only the connector and the reason;
// it is best effort and bounded.
var reportStandaloneHookRefusal = func(socket string, serviceUID int, connectorName, reason string) {
	if strings.TrimSpace(socket) == "" {
		return
	}
	client, err := hookexec.NewManagedStandaloneHookSocketHTTPClient(2*time.Second, socket, serviceUID)
	if err != nil {
		return
	}
	request, err := http.NewRequest(http.MethodPost, "http://defenseclaw-hook/api/v1/inspect/tool", strings.NewReader("{}"))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Connector", connectorName)
	request.Header.Set(hookexec.ClientRefusalHeader, reason)
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
}

// Test seams.
var (
	standaloneHookGOOS               = runtime.GOOS
	standaloneRuntimeDescriptorLoad  = managed.LoadRuntimeDescriptor
	standaloneMachinePolicyOptions   = defaultStandaloneMachinePolicyOptions
	standaloneSecureClientInstallDir = "/opt/cisco/secureclient/defenseclaw"
)

var standaloneHookRuntime struct {
	sync.Mutex
	prepared   bool
	connector  string
	layout     managed.StandaloneLayout
	descriptor *managed.RuntimeDescriptor
	reason     string
	// secureClientHost marks a macOS Secure Client host, whose
	// --enterprise-managed failures keep their historical results.
	secureClientHost bool
}

func trustedNativeHookHome() (string, bool) { return "", false }

// NativeHookRuntimeNoop is the Windows stable-launcher tombstone; unix has
// no such launcher.
func NativeHookRuntimeNoop() bool { return false }

func NativeConnectorHookNoop([]string) bool { return false }

// implicitEnterpriseManagedHook is Windows-only: unix standalone hooks select
// the managed runtime from the root-owned descriptor.
func implicitEnterpriseManagedHook() bool { return false }

// prepareEnterpriseManagedHookRuntime loads the Unix managed runtime and
// returns false because Unix has no launcher tombstone. A missing descriptor
// remains a fail-closed invocation even after machine policy is removed.
func prepareEnterpriseManagedHookRuntime(connectorName string) bool {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	contextReason := ""
	if standaloneHookGOOS == "linux" {
		contextReason = standaloneLinuxHookContext()
	}
	layout, err := managed.StandaloneLayoutFor(standaloneHookGOOS)
	var loaded *managed.RuntimeDescriptor
	if err == nil {
		loaded, err = standaloneRuntimeDescriptorLoad(layout.DescriptorPath)
	}
	// The trusted descriptor is the managed policy this hook enforces; only
	// a hook with no trusted descriptor at all refuses. The hook reads no
	// vendor policy file: a view the gateway can not prove still has every
	// call inspected under that policy, and the gateway raises the alert.
	reason := ""
	secureClientHost := false
	switch {
	case contextReason != "":
		reason = contextReason
	case err == nil && loaded != nil && strings.TrimSpace(loaded.HookSocket) == "":
		reason = standaloneRuntimeReasonHookSocketMissing
	case err == nil:
	case errors.Is(err, managed.ErrNoRuntimeDescriptor):
		switch {
		case standaloneHookGOOS == "darwin" && pathExists(standaloneSecureClientInstallDir):
			// A Secure Client host never uses this runtime; keep its
			// historical fail-closed result for --enterprise-managed.
			reason = standaloneRuntimeReasonInvalid
			secureClientHost = true
		default:
			reason = standaloneRuntimeReasonDescriptorMissing
		}
	default:
		reason = standaloneRuntimeReasonInvalid
	}
	standaloneHookRuntime.Lock()
	standaloneHookRuntime.prepared = true
	standaloneHookRuntime.connector = connectorName
	standaloneHookRuntime.layout = layout
	standaloneHookRuntime.descriptor = loaded
	standaloneHookRuntime.reason = reason
	standaloneHookRuntime.secureClientHost = secureClientHost
	if reason != "" {
		standaloneHookRuntime.descriptor = nil
	}
	standaloneHookRuntime.Unlock()
	return false
}

func enterpriseManagedHookRuntimeForceClosed() bool {
	standaloneHookRuntime.Lock()
	defer standaloneHookRuntime.Unlock()
	return standaloneHookRuntime.prepared && standaloneHookRuntime.reason != ""
}

// enterpriseManagedHookRuntimeFailMode is the fail mode the root-owned runtime
// descriptor records for the prepared connector (RuntimeDescriptor.HookFailMode):
// open only when the administrator's config chose open for it, and closed
// otherwise and whenever the runtime failed its checks.
func enterpriseManagedHookRuntimeFailMode() string {
	standaloneHookRuntime.Lock()
	defer standaloneHookRuntime.Unlock()
	if !standaloneHookRuntime.prepared || standaloneHookRuntime.reason != "" || standaloneHookRuntime.descriptor == nil {
		return "closed"
	}
	return standaloneHookRuntime.descriptor.HookFailMode(standaloneHookRuntime.connector)
}

func enterpriseManagedHookRuntimeFailureReason() string {
	standaloneHookRuntime.Lock()
	defer standaloneHookRuntime.Unlock()
	if !standaloneHookRuntime.prepared {
		return ""
	}
	return standaloneHookRuntime.reason
}

// enterpriseManagedHookRuntimeConnection returns the descriptor's gateway
// address. There is no service name and no scoped token: the standalone
// transport reaches the gateway only through the hook socket, which
// authenticates the gateway by uid, and the gateway authenticates this
// process by its kernel-verified uid.
func enterpriseManagedHookRuntimeConnection(connectorName string) (string, string, *string, bool) {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	standaloneHookRuntime.Lock()
	defer standaloneHookRuntime.Unlock()
	if !standaloneHookRuntime.prepared || standaloneHookRuntime.reason != "" ||
		standaloneHookRuntime.descriptor == nil || standaloneHookRuntime.connector != connectorName {
		return "", "", nil, false
	}
	return standaloneHookRuntime.descriptor.APIAddr, "", nil, true
}

// applyStandaloneManagedHookTransport binds the managed options to the
// descriptor after buildHookOptionsForRuntime resolved the endpoint:
// the unix socket and service uid select the verified transport, and the
// inherited environment may only tighten the result. When the standalone
// runtime failed its checks it selects no transport and only marks the
// options as the standalone profile's (ManagedStandalone), so the failure
// gets that profile's fail-closed results; a Secure Client host is never
// marked.
func applyStandaloneManagedHookTransport(opts *hookexec.Options, connectorName string) {
	if opts == nil || !opts.ManagedEnterprise {
		return
	}
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	standaloneHookRuntime.Lock()
	descriptor := standaloneHookRuntime.descriptor
	layout := standaloneHookRuntime.layout
	prepared := standaloneHookRuntime.prepared && standaloneHookRuntime.connector == connectorName
	failed := standaloneHookRuntime.reason != ""
	secureClientHost := standaloneHookRuntime.secureClientHost
	standaloneHookRuntime.Unlock()
	if opts.ManagedRuntimeFailure != "" {
		if prepared && failed && !secureClientHost {
			opts.ManagedStandalone = true
			if hookexec.IsManagedProcessContextReason(opts.ManagedRuntimeFailure) {
				serviceUID := -1
				if descriptor != nil {
					serviceUID = descriptor.ServiceUID
				}
				reportStandaloneHookRefusal(layout.HookSocketPath, serviceUID, connectorName, opts.ManagedRuntimeFailure)
			}
		}
		return
	}
	matches := prepared && !failed
	if !matches || descriptor == nil {
		return
	}
	opts.ManagedStandalone = true
	opts.ManagedServiceUID = descriptor.ServiceUID
	opts.ManagedUnixSocket = descriptor.HookSocket
	// opts.FailMode and StrictAvailability are the descriptor's
	// (enterpriseManagedHookRuntimeFailMode): closed and strict unless the
	// administrator's config chose open for this connector.
	// An inherited generic gateway token never authenticates a managed hook.
	opts.Token = ""
	if opts.MaxBody <= 0 || opts.MaxBody > 1<<20 {
		opts.MaxBody = 1 << 20
	}
	// Machine-policy connectors run this hook for users who have no
	// per-user DefenseClaw directory. Anchor Home at the
	// administrator-owned config directory: it always exists, and a user
	// cannot create a .disabled sentinel there. No token is read from it:
	// the hook socket authenticates this process by uid.
	opts.Home = layout.ConfigDir
	opts.HookDir = filepath.Join(layout.ConfigDir, "hooks")
}

// defaultStandaloneMachinePolicyOptions resolves the machine policy paths
// of the standalone layout for goos.
func defaultStandaloneMachinePolicyOptions(goos string) (enterprisepolicy.Options, bool) {
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		return enterprisepolicy.Options{}, false
	}
	return enterprisepolicy.LayoutOptions(layout, "", ""), true
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
