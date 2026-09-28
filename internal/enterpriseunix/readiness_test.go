// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// On macOS the gateway binds 127.0.0.1:18970 itself. A local process that
// bound the port first can answer /health while the real gateway retries its
// bind and launchd reports it running, and it never serves the hook socket.
// Readiness and verify require the gateway account on the hook socket.
func TestReadinessNeedsTheGatewayOnTheHookSocket(t *testing.T) {
	for name, peer := range map[string]func(h *testHost) (peercred.Credentials, error){
		"hook socket not served": func(*testHost) (peercred.Credentials, error) {
			return peercred.Credentials{}, errors.New("connection refused")
		},
		"hook socket served by another account": func(*testHost) (peercred.Credentials, error) {
			return peercred.Credentials{UID: 501, GID: 20}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			// Another process answers /health on the gateway port.
			h.env.APIHealthGet = func(context.Context) (int, []byte, error) { return 200, []byte(`{}`), nil }
			h.env.HookSocketPeer = func(context.Context) (peercred.Credentials, error) { return peer(h) }

			verify := h.run(Options{Action: ActionVerify})
			joined := ""
			for _, e := range verify.Errors {
				joined += e.Message + "\n"
			}
			if !strings.Contains(joined, "hook socket") {
				t.Fatalf("verify accepted a /health answer without the gateway on the hook socket: %+v", verify.Errors)
			}
			if status := h.run(Options{Action: ActionStatus}); status.Readiness.Gateway {
				t.Fatal("status reports the gateway ready without it on the hook socket")
			}

			r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
			requireError(t, r, codeActivate)
			if record, _ := h.env.loadDeployment(); record.ProductVersion != "1.0.0" {
				t.Fatalf("the upgrade committed without a serving gateway: %+v", record)
			}
		})
	}

	// Readiness needs the gateway on the hook socket on Linux too: its health
	// document is read there, so the listener must be PID 1 (the socket unit),
	// root, or the service account.
	t.Run("linux", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		h.env.HookSocketPeer = func(context.Context) (peercred.Credentials, error) {
			return peercred.Credentials{UID: 1001, GID: 1001, PID: 4321}, nil
		}
		if status := h.run(Options{Action: ActionStatus}); status.Readiness.Gateway {
			t.Fatal("status reports the gateway ready with another account on the hook socket")
		}
		if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); !strings.Contains(got, "is served by uid 1001") {
			t.Fatalf("verify does not name the hook socket listener: %s", got)
		}

		// systemd holds the socket-activated listener.
		h.env.HookSocketPeer = func(context.Context) (peercred.Credentials, error) {
			return peercred.Credentials{UID: 0, GID: 0, PID: 1}, nil
		}
		status := h.run(Options{Action: ActionStatus})
		if !status.Readiness.Gateway || status.Inspection.Local != "active" {
			t.Fatalf("a socket-activated hook socket must count as the gateway's: %+v %+v %+v", status.Readiness, status.Inspection, status.Warnings)
		}
	})
}

// plantLinuxListener makes the rooted /proc show pid listening on
// 127.0.0.1:18970 as uid.
func plantLinuxListener(t *testing.T, h *testHost, pid, uid string) {
	t.Helper()
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  " + uid + "        0 777001 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777002 1 0000000000000000 100 0 0 10 0\n"
	writeHostFile(t, h, "/proc/net/tcp", tcp)
	fd := h.env.P(filepath.Join("/proc", pid, "fd"))
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[777001]", filepath.Join(fd, "7")); err != nil {
		t.Fatal(err)
	}
	other := h.env.P("/proc/4000/fd")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[777002]", filepath.Join(other, "3")); err != nil {
		t.Fatal(err)
	}
}

// lsofRunner answers lsof like macOS does for a listener on the API port.
type lsofRunner struct {
	Runner
	output string
}

func (r lsofRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "lsof" {
		return CommandResult{Stdout: []byte(r.output)}, nil
	}
	return r.Runner.Run(ctx, name, args...)
}

// retryingAPIHealth is the gateway's /health document on its hook socket
// while another process holds the API port.
const retryingAPIHealth = `{"api":{"state":"error","last_error":"listen tcp 127.0.0.1:18970: bind: address already in use","details":{"addr":"127.0.0.1:18970","tcp_bind_retrying":true}},"inspection":{"local":"active","ai_defense":"disabled"}}`

// On Linux the gateway unit runs and serves its hook socket, but
// another account holds 127.0.0.1:18970 and the gateway reports its API
// listener as retrying. Status reported the gateway ready (a 200 was taken
// as readiness) and did not name the holder.
func TestGatewayWithoutItsAPIPortIsNotReadyAndNamesTheHolder(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	plantLinuxListener(t, h, "31337", "4242")
	h.env.HealthGet = func(context.Context) (int, []byte, error) { return 200, []byte(retryingAPIHealth), nil }
	want := "the gateway API port 127.0.0.1:18970 is held by pid 31337 (uid 4242"

	status := h.run(Options{Action: ActionStatus})
	if status.Readiness.Gateway || status.CoverageComplete {
		t.Fatalf("status reports the gateway ready without its API port: %+v", status.Readiness)
	}
	if got := messagesOf(status.Errors, codeVerify); !strings.Contains(got, want) || !strings.Contains(got, "serves hooks on its socket and keeps retrying the port") {
		t.Fatalf("status does not name the port holder: %s", got)
	}
	if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); !strings.Contains(got, want) {
		t.Fatalf("verify does not name the port holder: %s", got)
	}

	// When the holder cannot be seen (it exited, or lsof shows only the
	// caller's own processes), the gateway's own report still says why it is
	// not ready.
	t.Run("no visible holder", func(t *testing.T) {
		for _, goos := range []string{"linux", "darwin"} {
			t.Run(goos, func(t *testing.T) {
				h := newTestHost(t, goos)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				h.env.HealthGet = func(context.Context) (int, []byte, error) { return 200, []byte(retryingAPIHealth), nil }
				status := h.run(Options{Action: ActionStatus})
				if status.Readiness.Gateway {
					t.Fatal("status reports the gateway ready without its API port")
				}
				got := messagesOf(status.Errors, codeVerify)
				if !strings.Contains(got, "its API listener 127.0.0.1:18970 is not up (error: listen tcp 127.0.0.1:18970: bind: address already in use); the gateway keeps retrying the port") {
					t.Fatalf("status does not explain the API listener: %s", got)
				}
			})
		}
	})

	// With the socket units stopped another account bound
	// 127.0.0.1:18970. Repair failed with systemd's "Job failed. See journalctl
	// -xe" and status reported "gateway health: ... EOF" (the probe reached the
	// other process); neither named it.
	t.Run("linux socket units stopped", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		plantLinuxListener(t, h, "31337", "4242")
		h.services.active[unitAPISocket] = false
		h.services.active[unitGateway] = false
		// The other process closes connections on the port; the lifecycle no
		// longer asks it.
		h.env.APIHealthGet = func(context.Context) (int, []byte, error) {
			return 0, nil, errors.New(`Get "http://127.0.0.1:18970/health": EOF`)
		}
		// The hook socket is gone as well; Go's error for the request over it
		// names the API address and the dial.
		h.services.active[unitHookSocket] = false
		h.env.HealthGet = func(context.Context) (int, []byte, error) {
			return 0, nil, &url.Error{Op: "Get", URL: "http://127.0.0.1:18970/health", Err: &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ENOENT)}}
		}
		want := "the gateway API port 127.0.0.1:18970 is held by pid 31337 (uid 4242"
		socket := "the gateway does not serve the hook socket " + h.env.Layout.HookSocketPath + ": the socket file does not exist"

		status := h.run(Options{Action: ActionStatus})
		if got := messagesOf(status.Errors, codeVerify); !strings.Contains(got, want) || strings.Contains(got, "EOF") || !strings.Contains(got, "enterprise linux repair`") ||
			!strings.Contains(got, socket) || strings.Contains(got, "http://") {
			t.Fatalf("status does not name the port holder and the missing hook socket: %s", got)
		}
		if status.Readiness.Gateway {
			t.Fatal("status reports the gateway ready")
		}

		h.services.failStart[unitAPISocket] = errors.New("systemctl start defenseclaw-gateway-api.socket: exit 1: Job for defenseclaw-gateway-api.socket failed. See \"journalctl -xe\" for details.")
		repair := h.run(Options{Action: ActionRepair})
		requireError(t, repair, codeActivate)
		if got := messagesOf(repair.Errors, codeActivate); !strings.Contains(got, want) {
			t.Fatalf("repair does not name the port holder: %s", got)
		}
	})

	// While another account held 127.0.0.1:18970 across a gateway
	// restart, status said only "gateway health returned HTTP 503" (the other
	// listener's answer) and nothing about the gateway serving the hook socket.
	// Readiness now comes from the gateway's own report on its hook socket; the
	// answer on the port is never asked for.
	t.Run("darwin", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		h.env.Runner = lsofRunner{Runner: h.runner, output: "p94782\nu4243\nf5\n"}
		for name, answer := range map[string]int{"503": 503, "200": 200} {
			t.Run(name, func(t *testing.T) {
				h.env.HealthGet = func(context.Context) (int, []byte, error) { return 200, []byte(retryingAPIHealth), nil }
				h.env.APIHealthGet = func(context.Context) (int, []byte, error) {
					t.Error("the answer on the API port was asked for")
					return answer, []byte(`{"api":{"state":"running"}}`), nil
				}
				status := h.run(Options{Action: ActionStatus})
				got := messagesOf(status.Errors, codeVerify)
				if !strings.Contains(got, "is held by pid 94782 (uid 4243") || !strings.Contains(got, "serves hooks on its socket and keeps retrying the port") {
					t.Fatalf("status does not name the port holder: %s", got)
				}
				if status.Readiness.Gateway {
					t.Fatal("status reports the gateway ready while another process holds its API port")
				}
				verify := h.run(Options{Action: ActionVerify})
				if got := messagesOf(verify.Errors, codeVerify); strings.Count(got, "is held by pid 94782") != 1 {
					t.Fatalf("verify must name the port holder once: %s", got)
				}
			})
		}
	})
}

// A gateway from an earlier release refuses /health on its hook socket (the
// path has no connector scope there). Between a package upgrade and the
// restart, and after a rollback, readiness falls back to the TCP API; on
// macOS a process other than the gateway on that port still fails it.
func TestEarlierGatewayIsProbedOnTheAPIPort(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.HealthGet = func(context.Context) (int, []byte, error) {
				return http.StatusForbidden, []byte(`{"error":"forbidden","reason":"connector_unknown"}`), nil
			}
			h.env.APIHealthGet = func(context.Context) (int, []byte, error) {
				return 200, []byte(`{"inspection":{"local":"active","ai_defense":"disabled"}}`), nil
			}
			if status := h.run(Options{Action: ActionStatus}); !status.Readiness.Gateway || status.Inspection.Local != "active" {
				t.Fatalf("an earlier gateway answering on its API port must be ready: %+v %+v", status.Readiness, status.Warnings)
			}
			if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); strings.Contains(got, "gateway") {
				t.Fatalf("verify refused an earlier gateway answering on its API port: %s", got)
			}
			if goos != "darwin" {
				return
			}
			h.env.Runner = lsofRunner{Runner: h.runner, output: "p94782\nu4243\nf5\n"}
			status := h.run(Options{Action: ActionStatus})
			if status.Readiness.Gateway || !strings.Contains(messagesOf(status.Errors, codeVerify), "is held by pid 94782 (uid 4243") {
				t.Fatalf("an answer from another holder of the API port was trusted: %+v %+v", status.Readiness, status.Errors)
			}
		})
	}
}

// The production probe speaks HTTP over the hook socket, with the API
// address as Host, and returns the gateway's document.
func TestHookSocketProbesReadTheGateway(t *testing.T) {
	dir, err := os.MkdirTemp("", "dchh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "hook.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	hosts := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts <- r.Host
		if r.URL.Path != "/health" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"api": map[string]any{"state": "running"}})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	layout, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	layout.HookSocketPath = path
	env := &Env{GOOS: "linux", Layout: layout}
	env.fillDefaults()
	code, body, err := env.HealthGet(context.Background())
	if err != nil || code != http.StatusOK || !strings.Contains(string(body), `"running"`) {
		t.Fatalf("health over the hook socket: %d %s %v", code, body, err)
	}
	if host := <-hosts; host != layout.APIAddr {
		t.Fatalf("Host %q, want %q", host, layout.APIAddr)
	}
	env.Layout.HookSocketPath = filepath.Join(dir, "missing.sock")
	env.HealthGet = nil
	env.fillDefaults()
	if _, _, err := env.HealthGet(context.Background()); err == nil {
		t.Fatalf("a missing hook socket answered: %v", err)
	}

	// The production probe reports the listening process's kernel credentials.
	t.Run("peer credentials", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "dchs")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		path := filepath.Join(dir, "hook.sock")
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		peer, err := hookSocketPeer(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		if peer.UID != os.Geteuid() {
			t.Fatalf("peer uid %d, want %d", peer.UID, os.Geteuid())
		}
		if peer.PID != 0 && peer.PID != os.Getpid() {
			t.Fatalf("peer pid %d, want %d", peer.PID, os.Getpid())
		}
		if _, err := hookSocketPeer(context.Background(), filepath.Join(dir, "missing.sock")); err == nil {
			t.Fatal("a missing hook socket was reported as served")
		}
	})
}
