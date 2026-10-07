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

package openshell

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The package gateway of an account that never ran NVIDIA's installer (the
// package was installed machine-wide by someone else) has a stopped
// service and no registration. The installer starts the service, waits for
// the client certificates the gateway writes on its first start, and
// registers it; the doctor's service fix does the same (registerLocal), or
// the registration's wait for a healthy gateway could never succeed.

// configDir is the OpenShell user configuration directory the registration
// is looked up in.
func (r *doctorRun) configDir() (string, error) {
	dir := r.Discover.ConfigDir
	if dir == "" {
		var err error
		if dir, err = UserConfigDir(); err != nil {
			return "", err
		}
	}
	return resolveConfigDir(dir)
}

// canRegisterLocal reports that the package gateway's registration is
// missing and registering it is what would select it: no other gateway is
// pinned, active or registered.
func (r *doctorRun) canRegisterLocal() bool {
	if r.Discover.Gateway != "" && r.Discover.Gateway != DefaultGatewayName {
		return false
	}
	dir, err := r.configDir()
	if err != nil {
		return false
	}
	if _, err := os.Lstat(filepath.Join(dir, gatewaysSubdir, DefaultGatewayName, metadataFile)); !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if active, err := readActiveGateway(filepath.Join(dir, activeGatewayFile)); err != nil || (active != "" && active != DefaultGatewayName) {
		return false
	}
	systemDir := r.Discover.SystemDir
	if systemDir == "" {
		systemDir = defaultSystemDir
	}
	for _, name := range listRegistrations(dir, systemDir) {
		if name != DefaultGatewayName {
			return false
		}
	}
	return true
}

// addCommand registers the package gateway the way NVIDIA's installer
// does.
func (r *doctorRun) addCommand() serviceCommand {
	host := "127.0.0.1"
	if r.GOOS == "darwin" {
		host = "localhost"
	}
	endpoint := "https://" + net.JoinHostPort(host, strconv.Itoa(r.gatewayPort()))
	return serviceCommand{r.CLI, []string{"gateway", "add", endpoint, "--local", "--name", DefaultGatewayName}}
}

// registerLocal registers the package gateway once it has written its
// client certificates (canRegisterLocal), after its service started.
func (r *doctorRun) registerLocal(ctx context.Context) error {
	dir, err := r.configDir()
	if err != nil {
		return err
	}
	mtls := filepath.Join(dir, gatewaysSubdir, DefaultGatewayName, mtlsSubdir)
	wait := r.Gateway.RestartWait
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	for !clientBundle(mtls) {
		if sleepContext(waitCtx, time.Second) != nil {
			return fmt.Errorf("the gateway started, but wrote no client certificates to %s within %s, so it cannot be registered; %s",
				mtls, wait, r.gatewayLogHint())
		}
	}
	add := r.addCommand()
	if out, err := r.Runner.Output(ctx, Command{Name: add.name, Args: add.args, Timeout: time.Minute}); err != nil {
		return fmt.Errorf("register the gateway: %s: %v: %s", add, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// clientBundle reports that dir holds the client certificates a local
// registration takes.
func clientBundle(dir string) bool {
	for _, name := range []string{"ca.crt", "tls.crt", "tls.key"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
}

func (r *doctorRun) gatewayLogHint() string {
	if r.GOOS == "darwin" {
		return "see `brew services info " + GatewayFormula + "`"
	}
	return "see `journalctl --user -u " + GatewayService + "`"
}

// gatewayPort is the port the gateway service listens on.
func (r *doctorRun) gatewayPort() int {
	env := map[string]string{}
	if r.service != nil {
		for k, v := range r.service.Environment {
			env[k] = v
		}
	}
	st := r.config
	if st == nil {
		st = &GatewayConfigState{}
	}
	for k, v := range st.Env {
		env[k] = v
	}
	if _, port, err := st.listenAddress(env); err == nil {
		if p, err := strconv.Atoi(port); err == nil && p > 0 && p <= 65535 {
			return p
		}
	}
	return defaultGatewayPort
}

// gatewayPortHeld says what holds the gateway's port while its service
// does not run ("" when the port is free): a start would leave the service
// restarting, unable to bind. other is another account's process: one
// OpenShell gateway runs on a machine, and the port is the first account's.
func (r *doctorRun) gatewayPortHeld() (held string, other bool) {
	port := r.gatewayPort()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := r.Listen("tcp", addr)
	if err == nil {
		_ = ln.Close()
		return "", false
	}
	if !errors.Is(err, syscall.EADDRINUSE) && !strings.Contains(err.Error(), "address already in use") {
		return "", false
	}
	who := "another process"
	if holder, err := r.PortHolder("127.0.0.1", port); err == nil {
		who = holder.String(r.Geteuid())
		other = holder.UID >= 0 && holder.UID != r.Geteuid()
	}
	return addr + ", the gateway's port, is held by " + who, other
}

// portHeldFix is the Gateway service fix while something else holds the
// gateway's port: nothing to start until it is free.
func (r *doctorRun) portHeldFix(other bool) *Fix {
	start := r.startCommand().String()
	if other {
		handOver := "`" + r.handOverCommand().String() + "` as that account"
		if r.GOOS != "darwin" {
			// A plain stop leaves the unit enabled: it starts again at
			// that account's next login or boot and takes the port back
			// (GAP-0205).
			handOver += "; a plain stop starts it again at that account's next login"
		}
		return &Fix{Summary: "one OpenShell gateway runs on a machine, under the account that started it, and this account's would not get its port: " +
			"run sandboxes from that account, or have it hand its gateway over (" + handOver + "), then start this one",
			Command: start}
	}
	return &Fix{Summary: "stop what holds the port (another OpenShell gateway, for one), then start the service", Command: start}
}

// handOverCommand stops the gateway service for good, so that another
// account can run the machine's one gateway: on Linux it also disables the
// unit; `brew services stop` already unregisters it from login.
func (r *doctorRun) handOverCommand() serviceCommand {
	if r.GOOS == "darwin" {
		return r.stopCommand()
	}
	return serviceCommand{"systemctl", []string{"--user", "disable", "--now", GatewayService}}
}
