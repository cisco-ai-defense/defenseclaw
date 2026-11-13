// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// Package hookuser is the per-user Unix Claude Code native hook: the body of
// defenseclaw-hook-user, shared with defenseclaw-hook-post guard-user-hook so
// the guard leg answers in one process (S8 B2). hookexec supplies the
// response and transport rules.
package hookuser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// RegisteredArgs is the data folder and gateway address of a registered
// hook command line (hook --connector claudecode --hook-home H [--api-addr A]).
func RegisteredArgs(args []string) (home, addr string, ok bool) {
	if len(args) != 5 && len(args) != 7 {
		return "", "", false
	}
	if args[0] != "hook" || args[1] != "--connector" || args[2] != "claudecode" ||
		args[3] != "--hook-home" || !validHome(args[4]) {
		return "", "", false
	}
	if len(args) == 7 {
		if args[5] != "--api-addr" || !loopbackAddr(args[6]) {
			return "", "", false
		}
		addr = args[6]
	}
	return args[4], addr, true
}

func validHome(home string) bool {
	return filepath.IsAbs(home) && filepath.Clean(home) == home && !strings.ContainsAny(home, "\x00\r\n")
}

// Run is the per-user native Claude Code hook (defenseclaw-hook-user
// hook ...): native is the installed defenseclaw-hook-user path, which names
// the account's bin folder for its trusted gateway. hook-user runs it for its
// own registration and fallback leg, and hook-post's guard-user-hook runs it
// in its own process (S8 B2), so the guard leg is one process.
func Run(native, home, addr string, stdin io.Reader, stdout, stderr io.Writer, startedAt time.Time) int {
	if !validHome(home) {
		return 2
	}
	// A personal registration cannot approve a call on a managed host.
	if managedRuntimePresent() {
		fmt.Fprintln(stderr, "defenseclaw: this computer is managed; the personal Claude Code hook cannot approve this call")
		return 2
	}
	// The existing script honors a different inherited data directory. Keep
	// that registration's behavior when the agent provides one.
	if inherited := os.Getenv("DEFENSECLAW_HOME"); inherited != "" && inherited != home {
		return runLegacyScript(home, stdin, stdout, stderr)
	}
	payload, _ := io.ReadAll(io.LimitReader(stdin, hookexec.DefaultMaxBody+1))
	payload = hookexec.TrimUTF8BOM(payload)
	input := io.MultiReader(bytes.NewReader(payload), stdin)
	watchdog := hookexec.ArmAnswerWatchdog(hookexec.Options{
		Connector: "claudecode", Home: home, StartedAt: startedAt,
		FailMode: "closed", Exit: ExitStoppingLooks, Stdout: stdout, Stderr: stderr,
	}, payload)
	hookDir := filepath.Join(home, "hooks")
	if addr == "" {
		addr = sidecarAddress(filepath.Join(hookDir, ".hookcfg"))
	}
	if !loopbackAddr(addr) {
		addr = "127.0.0.1:18970"
	}
	gateway := trustedGatewayAt(native, home)
	opts := hookexec.Options{
		Connector: "claudecode", APIAddr: addr, Home: home, HookDir: hookDir,
		FailMode: "closed", StartedAt: startedAt, Stdin: input,
		Stdout: stdout, Stderr: stderr, Exit: ExitStoppingLooks, AnswerWatchdog: watchdog,
		StrictAvailability: envTrue(os.Getenv("DEFENSECLAW_STRICT_AVAILABILITY")),
		TraceParent:        firstNonEmpty(os.Getenv("DEFENSECLAW_TRACEPARENT"), os.Getenv("TRACEPARENT"), os.Getenv("OTEL_TRACEPARENT")),
		TraceState:         firstNonEmpty(os.Getenv("DEFENSECLAW_TRACESTATE"), os.Getenv("TRACESTATE"), os.Getenv("OTEL_TRACESTATE")),
	}
	// DEFENSECLAW_HOOK_MAX_BODY can only lower the body cap, as in the shell
	// hook this command replaces: a call over a cap lowered under the
	// per-user transport's 900 KiB is refused (rel-1-0-6:GAP-0578).
	if maxBody, ok := hookexec.LoweredMaxBody(os.Getenv("DEFENSECLAW_HOOK_MAX_BODY")); ok {
		opts.MaxBody, opts.MaxBodyLowered = maxBody, maxBody < hookexec.DefaultMaxBody
	}
	if gateway != "" {
		opts.OutageFailModeNow = func() string {
			return sharedOutageMode(gateway, hookDir, time.Now(), func() string { return outageMode(gateway, hookDir) })
		}
		opts.GatewayRecovery = gatewayRecovery(gateway, home)
	}
	return hookexec.Run(context.Background(), opts)
}

func managedRuntimePresent() bool {
	return managedRuntimePresentAt(
		"/etc/defenseclaw/managed-runtime.json",
		"/opt/cisco/defenseclaw/etc/managed-runtime.json",
	)
}

func managedRuntimePresentAt(paths ...string) bool {
	for _, path := range paths {
		_, err := os.Lstat(path)
		if err == nil || !os.IsNotExist(err) {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runLegacyScript(home string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := exec.Command(filepath.Join(home, "hooks", "claude-code-hook.sh"))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode()
		}
		return 2
	}
	return 0
}

func sidecarAddress(path string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64<<10 {
		return ""
	}
	var current struct {
		Version     int    `json:"version"`
		GatewayAddr string `json:"gateway_addr"`
	}
	if json.Unmarshal(data, &current) == nil && current.Version >= 2 {
		return current.GatewayAddr
	}
	trimmed := bytes.TrimSpace(data)
	if json.Valid(trimmed) || (len(trimmed) != 0 && (trimmed[0] == '{' || trimmed[0] == '[')) {
		return ""
	}
	address := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "DEFENSECLAW_GATEWAY_ADDR" {
			continue
		}
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			address = unquoted
		} else {
			address = strings.Trim(value, `"'`)
		}
	}
	return address
}

func loopbackAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host := addr
	if parsed, _, err := net.SplitHostPort(addr); err == nil {
		host = parsed
	}
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envTrue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func trustedGatewayAt(self, home string) string {
	if filepath.Base(self) != "defenseclaw-hook-user" {
		return ""
	}
	binDir := filepath.Dir(self)
	if filepath.Base(binDir) != "bin" || filepath.Base(filepath.Dir(binDir)) != ".local" {
		return ""
	}
	uid := os.Geteuid()
	for _, dir := range []string{filepath.Join(home, "hooks"), home,
		filepath.Dir(filepath.Dir(binDir)), filepath.Dir(binDir), binDir} {
		info, err := os.Lstat(dir)
		if err != nil {
			return ""
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || !ok || stat.Uid != uint32(uid) || info.Mode().Perm()&0o022 != 0 {
			return ""
		}
	}
	gateway := filepath.Join(binDir, "defenseclaw-gateway")
	info, err := os.Lstat(gateway)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(uid) {
		return ""
	}
	record := filepath.Join(home, "hooks", ".gateway-helper")
	info, err = os.Lstat(record)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4097 || info.Mode().Perm()&0o022 != 0 {
		return ""
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(uid) {
		return ""
	}
	data, err := os.ReadFile(record)
	if err != nil || (string(data) != gateway && string(data) != gateway+"\n") {
		return ""
	}
	return gateway
}

func outageMode(gateway, hookDir string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const check = `ulimit -S -v "$(ulimit -H -v)" 2>/dev/null || true
exec "$1" hook-outage-mode --connector claudecode --hook-dir "$2"`
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", check, "defenseclaw-hook-user-outage", gateway, hookDir)
	cmd.Env = gatewayEnv(gateway, filepath.Dir(hookDir))
	output, stopped, err := runOutageLook(cmd)
	if stopped {
		// hook-user is exiting: no mode, and no result for other calls.
		return ""
	}
	if err == nil && strings.TrimSpace(string(output)) == "open" {
		return "open"
	}
	return "closed"
}

func gatewayRecovery(gateway, home string) func(context.Context, error) error {
	return func(ctx context.Context, _ error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if env := strings.ToLower(strings.TrimSpace(envvars.Getenv("DEFENSECLAW_GATEWAY_AUTOSTART"))); env == "0" || env == "false" || env == "no" || env == "off" {
			return fmt.Errorf("gateway autostart disabled")
		}
		if fileExists(filepath.Join(home, "gateway.stopped")) {
			return fmt.Errorf("gateway start deferred")
		}
		config, err := os.Stat(filepath.Join(home, "config.yaml"))
		if err != nil || !config.Mode().IsRegular() {
			return fmt.Errorf("gateway configuration unavailable")
		}
		if hookexec.PerUserGatewayStartInProgress(home) {
			return nil
		}
		lease, err := acquireColdStartLease(home)
		if err != nil {
			return err
		}
		if lease == nil {
			return nil
		}
		const start = `ulimit -S -t "$(ulimit -H -t)" 2>/dev/null || true
ulimit -S -v "$(ulimit -H -v)" 2>/dev/null || true
lock=$1; token=$2; gateway=$3
trap 'IFS= read -r line < "$lock" 2>/dev/null || true; [ "${line#* }" = "$token" ] && rm -f -- "$lock"' EXIT
"$gateway" start --hook-cold-start`
		cmd := exec.Command("/bin/sh", "-c", start, "defenseclaw-hook-user-start", lease.path, lease.token, gateway)
		cmd.Dir = filepath.Dir(gateway)
		cmd.Env = gatewayEnv(gateway, home)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			lease.release()
			return err
		}
		go func() { _ = cmd.Wait() }()
		return nil
	}
}

type coldStartLease struct {
	path, token string
	release     func()
}

func acquireColdStartLease(home string) (*coldStartLease, error) {
	lock := filepath.Join(home, ".cold-start.lock")
	create := func() (*coldStartLease, error) {
		file, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		owned, err := file.Stat()
		token := fmt.Sprintf("%d.%d", os.Getpid(), time.Now().UnixNano())
		if err == nil {
			_, err = fmt.Fprintf(file, "%d %s\n", time.Now().Unix(), token)
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(lock)
			return nil, err
		}
		return &coldStartLease{path: lock, token: token, release: func() {
			if current, statErr := os.Lstat(lock); statErr == nil && os.SameFile(current, owned) {
				_ = os.Remove(lock)
			}
		}}, nil
	}
	lease, err := create()
	if err == nil || !os.IsExist(err) {
		return lease, err
	}
	if !staleColdStartLock(lock, 120*time.Second) {
		return nil, nil
	}
	guard := lock + ".break"
	file, err := os.OpenFile(guard, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) && staleColdStartLock(guard, 5*time.Second) {
			_ = os.Remove(guard)
		}
		return nil, nil
	}
	_, _ = fmt.Fprintln(file, time.Now().Unix())
	_ = file.Close()
	defer os.Remove(guard)
	if staleColdStartLock(lock, 120*time.Second) {
		_ = os.Remove(lock)
	}
	lease, err = create()
	if os.IsExist(err) {
		return nil, nil
	}
	return lease, err
}

func staleColdStartLock(path string, age time.Duration) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if info.Size() <= 128 {
		if file, err := os.Open(path); err == nil {
			data, _ := io.ReadAll(io.LimitReader(file, 129))
			_ = file.Close()
			if len(data) > 128 {
				return false
			}
			if fields := strings.Fields(string(data)); len(fields) != 0 {
				if stamp, err := strconv.ParseInt(fields[0], 10, 64); err == nil && stamp >= 0 {
					elapsed := time.Now().Unix() - stamp
					return elapsed < 0 || elapsed >= int64(age/time.Second)
				}
			}
		}
	}
	return time.Since(info.ModTime()) >= 2*time.Minute
}

func gatewayEnv(gateway, dataDir string) []string {
	binDir := filepath.Dir(gateway)
	accountHome := filepath.Dir(filepath.Dir(binDir))
	environ := os.Environ()
	out := make([]string, 0, len(environ)+5)
	for _, entry := range environ {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "DEFENSECLAW_") || strings.HasPrefix(upper, "OPENCLAW_") ||
			strings.HasPrefix(upper, "PYTHON") || strings.HasPrefix(upper, "GIT_") ||
			strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") ||
			upper == "HOME" || upper == "PATH" || upper == "LC_ALL" || upper == "LANG" {
			continue
		}
		out = append(out, entry)
	}
	return append(out, "HOME="+accountHome,
		"PATH="+binDir+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"DEFENSECLAW_HOME="+dataDir, "PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
}
