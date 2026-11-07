// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Seams for tests.
var (
	gatewayPortHolder         = daemon.FindPortHolder
	gatewayPortAnswers        = gatewayPortAcceptsConnections
	gatewayManagedState       = func() (bool, int) { return daemon.New(config.DefaultDataPath()).IsRunning() }
	gatewayRunsReplacedBinary = func() bool { return daemon.New(config.DefaultDataPath()).RunsReplacedExecutable() }
	gatewayExecutable         = os.Executable
	gatewayListenerClass      = daemon.ClassifyPerUserListener
)

// foreignGatewayListener explains a listener on the configured API port that
// is not the gateway this account started with `defenseclaw-gateway start`
// for this DefenseClaw home: a gateway left running by another home or test
// run, another account's process, or any other program. It returns "" when
// the port is free, the managed gateway owns it, or the connected-peer check
// must decide ownership of an unlisted process from this account.
//
// An unlisted account process reaches the separate connected-peer check;
// this diagnosis never sends a gateway token. Managed deployments run
// the gateway as a service, so they keep their own checks. On Windows the
// holder is named by PID and program (GAP-1344): status showed another
// account's gateway on this account's port as this account's, rc 0.
func foreignGatewayListener(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return foreignGatewayListenerAt(cfg, gatewayClientHost(cfg), cfg.Gateway.APIPort)
}

// foreignGatewayListenerAt is foreignGatewayListener for the API listener at
// host:port, for a caller that resolved the address from its own view of the
// configuration (the observability-v8 helpers). cfg may be nil.
func foreignGatewayListenerAt(cfg *config.Config, host string, port int) string {
	if (cfg != nil && (cfg.StandaloneEnterprise() || managed.IsManagedEnterprise(cfg.DeploymentMode))) ||
		managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return ""
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	holder, holderErr := gatewayPortHolder(host, port)
	// lsof on macOS does not list another account's sockets, so a missing
	// holder is confirmed with a connection attempt. The PID record may then
	// identify a root-run gateway for this home for diagnosis only.
	if holderErr != nil && !gatewayPortAnswers(addr) {
		return ""
	}
	if holderErr != nil {
		holder = daemon.PortHolder{UID: -1}
	}
	class := gatewayListenerClass(host, port, config.DefaultDataPath(), holder, holderErr, holderErr != nil)
	if class == daemon.PerUserListenerOwnGatewayRunAsRoot {
		return daemon.RootGatewayListenerReason
	}
	if class == daemon.PerUserListenerOwnGateway || class == daemon.PerUserListenerUnlistedOwnProcess {
		return ""
	}
	running, managedPID := gatewayManagedState()
	ownUID := os.Getuid()
	who := holder.String(ownUID)
	if label := listenerProcessLabel(holder.PID); label != "" {
		who += " (" + label + ")"
	}
	switch {
	case holderErr == nil && holder.UID >= 0 && holder.UID != ownUID:
		return fmt.Sprintf("%s is held by %s, not by this account's gateway", addr, who)
	// Windows names no UID for the holder or this account (both -1); its
	// platform proof compares the process token's user instead.
	case holderErr == nil && holder.UID == ownUID && sameHomeGatewayProcess(holder.PID, config.DefaultDataPath()):
		return ""
	case holderErr != nil:
		return fmt.Sprintf("%s is held by %s, not by this account's verified gateway", addr, who)
	case !running:
		return fmt.Sprintf(
			"%s is held by %s, not by this account's gateway: no gateway started for %s is running",
			addr, who, config.DefaultDataPath(),
		)
	case holderErr == nil && holder.PID > 0 && holder.PID != managedPID:
		return fmt.Sprintf(
			"%s is held by %s, not by this account's gateway (PID %d)", addr, who, managedPID,
		)
	}
	return ""
}

// sameHomeGatewayProcess recognises a gateway launched without a daemon PID
// file, such as a transient service. The listener's account is checked by
// the caller before this process identity is accepted.
func sameHomeGatewayProcess(pid int, home string) bool {
	if pid <= 0 || !filepath.IsAbs(home) {
		return false
	}
	executable, err := gatewayExecutable()
	if err != nil || !gatewayExecutableName(executable, runtime.GOOS) {
		return false
	}
	return sameHomeGatewayProcessPlatform(pid, home, executable)
}

// gatewayExecutableName reports whether executable is the gateway program:
// defenseclaw-gateway, or defenseclaw-gateway.exe on Windows (GAP-0694).
func gatewayExecutableName(executable, goos string) bool {
	if goos == "windows" {
		return strings.EqualFold(filepath.Base(executable), "defenseclaw-gateway.exe")
	}
	return filepath.Base(executable) == "defenseclaw-gateway"
}

// foregroundLaunchHome is the DefenseClaw home of a gateway launched with
// environment, by the rule of config.DefaultDataPath: a non-empty
// DEFENSECLAW_HOME, otherwise HOME's .defenseclaw. Linux and macOS share it,
// so a foreground gateway on the default home is recognised on both
// (GAP-0705). A relative or repeated value proves nothing.
func foregroundLaunchHome(environment []string) (string, bool) {
	return foregroundLaunchHomeFrom(environment, "HOME")
}

// foregroundLaunchHomeFrom is foregroundLaunchHome for a platform whose
// account home variable is userHomeKey (USERPROFILE on Windows, the one
// os.UserHomeDir reads).
func foregroundLaunchHomeFrom(environment []string, userHomeKey string) (string, bool) {
	var override, userHome string
	seenOverride, seenHome := false, false
	for _, entry := range environment {
		switch {
		case strings.HasPrefix(entry, "DEFENSECLAW_HOME="):
			if seenOverride {
				return "", false
			}
			seenOverride, override = true, strings.TrimPrefix(entry, "DEFENSECLAW_HOME=")
		case strings.HasPrefix(entry, userHomeKey+"="):
			if seenHome {
				return "", false
			}
			seenHome, userHome = true, strings.TrimPrefix(entry, userHomeKey+"=")
		}
	}
	if override != "" {
		if !filepath.IsAbs(override) {
			return "", false
		}
		return override, true
	}
	if filepath.IsAbs(userHome) {
		return filepath.Join(userHome, config.DefaultDataDirName), true
	}
	return "", false
}

// sameForegroundFile reports whether two absolute paths name one file, so a
// link to the gateway counts and a copy of it does not.
func sameForegroundFile(left, right string) bool {
	if !filepath.IsAbs(left) || !filepath.IsAbs(right) {
		return false
	}
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}

// otherAccountListenerAt explains a listener on host:port that belongs to
// another account, and nothing else. foreignGatewayListenerAt also compares
// the holder with this account's managed gateway, which the installer's
// pre-flight cannot do for an older release: it would call this account's own
// running gateway foreign. Linux names the holder's account; lsof on macOS
// lists only this account's sockets, so a listener nobody lists that answers
// is another account's.
func otherAccountListenerAt(host string, port int) string {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	holder, err := gatewayPortHolder(host, port)
	ownUID := os.Getuid()
	var who string
	switch {
	case err == nil && holder.UID >= 0 && holder.UID != ownUID:
		who = holder.String(ownUID)
	case errors.Is(err, daemon.ErrNoListener) && gatewayPortAnswers(addr):
		who = "a process of another account"
	default:
		return ""
	}
	return fmt.Sprintf("%s is held by %s, not by this account's gateway", addr, who)
}

// problemClause is a foreignGatewayListener problem inside a longer sentence:
// the root-gateway reason is a full sentence with its own final period, which
// the surrounding text must not double (GAP-0706).
func problemClause(problem string) string {
	return strings.TrimSuffix(problem, ".")
}

// explainForeignListenerAtReadiness names the holder when another listener
// answered readiness on the API port. The start check passed, but another
// account's gateway took the port before this one bound it, and start
// reported only "gateway identity mismatch: authenticated status returned
// 401 Unauthorized" (GAP-1285). Readiness no longer sends the token to that
// listener (GAP-1967), so the gateway, which then cannot bind the port,
// often exits first: that exit names the holder too.
func explainForeignListenerAtReadiness(cfg *config.Config, err error) error {
	if cfg == nil || !(errors.Is(err, errGatewayIdentityMismatch) || errors.Is(err, errGatewayExitedBeforeReadiness)) {
		return err
	}
	if problem := foreignGatewayListener(cfg); problem != "" {
		return fmt.Errorf("%w: %s. %s", err, problemClause(problem), foreignGatewayListenerFix(cfg))
	}
	return err
}

// foreignGatewayListenerFix is the next step for foreignGatewayListener. On a
// shared machine the holder is often another account's gateway on the same
// default port, so it names the command that moves this account's gateway
// and, when one is free, a port to use.
//
// status, start, restart and policy reload all use this text, so they give
// the same command; another account's process is not this account's to stop
// (GAP-1706).
func foreignGatewayListenerFix(cfg *config.Config) string {
	return foreignGatewayListenerFixAt(gatewayClientHost(cfg), cfg.Gateway.APIPort)
}

// foreignGatewayListenerFixAt is foreignGatewayListenerFix for the API
// listener at host:apiPort (the observability-v8 helpers, GAP-1670).
func foreignGatewayListenerFixAt(host string, apiPort int) string {
	holder, err := gatewayPortHolder(host, apiPort)
	if err != nil {
		holder = daemon.PortHolder{UID: -1}
	}
	if gatewayListenerClass(host, apiPort, config.DefaultDataPath(), holder, err,
		err != nil && gatewayPortAnswers(net.JoinHostPort(host, strconv.Itoa(apiPort)))) == daemon.PerUserListenerOwnGatewayRunAsRoot {
		return daemon.RootGatewayListenerRemedy(config.DefaultDataPath())
	}
	port := "<free port>"
	if free := freeGatewayAPIPort(host, apiPort); free > 0 {
		port = strconv.Itoa(free)
	}
	move := fmt.Sprintf(
		"move this account's gateway to a free port with: defenseclaw setup gateway --api-port %s --non-interactive, then run: defenseclaw-gateway start",
		port,
	)
	if gatewayPortHeldByOtherAccount(host, apiPort) {
		return "That process belongs to another account, so " + move
	}
	return "Stop that process, or " + move
}

// gatewayPortHeldByOtherAccount reports whether another account's process
// holds host:port. An unnamed holder on Linux and macOS counts as another
// account's: lsof does not list other accounts' sockets. A seam for tests.
var gatewayPortHeldByOtherAccount = func(host string, port int) bool {
	if runtime.GOOS == "windows" {
		return gatewayListenerOfAnotherAccount(host, port, "")
	}
	holder, err := gatewayPortHolder(host, port)
	if err != nil {
		return true
	}
	return holder.UID >= 0 && holder.UID != os.Getuid()
}

// gatewayAPIPortStep keeps a suggested API port clear of the sandbox ingress
// and egress ports a gateway uses next to its own (api_port+1 and +2), the
// same step init uses when it moves a new account off a held port.
const gatewayAPIPortStep = 10

// gatewayAPIPortTries is how many candidates a suggestion looks at. It
// matches bootstrap._FIRST_RUN_API_PORT_TRIES, so the gateway, doctor,
// init and setup gateway search the same window (GAP-1807).
const gatewayAPIPortTries = 50

// freeGatewayAPIPort returns the first port after from, in steps of
// gatewayAPIPortStep, that host can bind right now together with its two
// sandbox ports and that no other account has claimed, or 0 when none of
// the next gatewayAPIPortTries is. setup gateway refuses a port another
// account claimed, so suggesting one sent the user in a circle (GAP-1762).
func freeGatewayAPIPort(host string, from int) int {
	for step := 1; step <= gatewayAPIPortTries; step++ {
		port := from + step*gatewayAPIPortStep
		if port+2 > 65535 {
			break
		}
		if !gatewayPortClaimedByOtherAccount(port) && gatewayPortsBindable(host, port, port+1, port+2) {
			return port
		}
	}
	return 0
}

func gatewayPortsBindable(host string, ports ...int) bool {
	for _, port := range ports {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return false
		}
		_ = ln.Close()
	}
	return true
}

func gatewayPortAcceptsConnections(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
