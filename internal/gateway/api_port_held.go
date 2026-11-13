// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// routePortHeldName marks, under <dataDir>/hooks, that another account held
// the API port of this OSS gateway while route-only was on. The route key is
// replaced once the gateway owns the port again (S1 DESIGN 16.2, 17.1, 18.4);
// doctor reports the mark until then.
const routePortHeldName = ".route-port-held.json"

type routePortHeld struct {
	// UID is the account that held the port, from /proc/net on Linux. It
	// is absent on Windows, where the bind error proves another account
	// but does not name it.
	UID  *int      `json:"uid,omitempty"`
	Addr string    `json:"addr"`
	At   time.Time `json:"at"`
}

func (m routePortHeld) holder() string {
	if m.UID == nil {
		return "another account"
	}
	return fmt.Sprintf("another account (uid %d)", *m.UID)
}

// apiPortSelfUID is the account this gateway runs as; replaceable in tests.
var apiPortSelfUID = os.Getuid

// apiPortHeldByAnotherAccount is isAPIPortHeldByAnotherAccount (Windows
// WSAEACCES under another account wildcard listener); replaceable in tests.
var apiPortHeldByAnotherAccount = isAPIPortHeldByAnotherAccount

// routeOnlyConnectorsOf lists the route-only connectors config.yaml routes.
func routeOnlyConnectorsOf(cfg *config.Config) []string {
	if cfg == nil || !cfg.Routing.Enabled {
		return nil
	}
	return cfg.Routing.RouteOnly.Connectors
}

// ossRouteOnlyGateway reports whether this gateway renders the route-only
// agent configs itself and owns the OSS route key: no managed deployment
// (the guardian renders per enrolled user there, and the route epoch and
// the per-user keys rotate). One rule for the held-port mark, the key
// rotation and the re-render.
func ossRouteOnlyGateway(cfg *config.Config) bool {
	return cfg != nil && !cfg.StandaloneEnterprise() && !managed.IsManagedEnterprise(cfg.DeploymentMode)
}

// noteHeldAPIPort is the onHeld of the API binds: it looks for the holder
// at every bind conflict until one is noted (once per acquireAPIListener).
func (a *APIServer) noteHeldAPIPort(bindErr error) {
	if a.apiPortHolderNoted.Load() {
		return
	}
	if a.noteAPIPortHolder(bindErr) {
		a.apiPortHolderNoted.Store(true)
	}
}

// noteAPIPortHolder runs at a bind of the API address that found it held
// and reports whether the holder is settled. On Windows the bind error
// proves another account (apiPortHeldByAnotherAccount; the account is not
// named), on Linux /proc/net/tcp and tcp6 name its uid. No holder found, or
// this account (its own gateway still exiting during a restart), returns
// false so the next conflict looks again: another account can take the port
// in the gap before the next attempt (S1 DESIGN 16.2, 17.1). Another
// account is audited (gateway-degraded, HIGH) and named on stderr; with
// route-only on an OSS gateway the mark is written. The route credential is
// not rotated now: whoever holds the port would get the new one too. It is
// replaced when this gateway owns the port again
// (rotateRouteKeyAfterHeldPort).
func (a *APIServer) noteAPIPortHolder(bindErr error) bool {
	cfg := a.liveConfig()
	held := routePortHeld{Addr: a.addr}
	details := ""
	if apiPortHeldByAnotherAccount(bindErr) {
		if !ossRouteOnlyGateway(cfg) {
			// Managed Windows starts a new route epoch instead (startRouteEpoch).
			return true
		}
		details = fmt.Sprintf("api port %s held by another account (bind refused: access denied)", a.addr)
	} else {
		self := apiPortSelfUID()
		uid, found, err := apiPortHolderUID(a.addr, self)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar-api] could not read which account holds %s: %v\n", a.addr, err)
			return true
		}
		if !found || uid == self {
			return false
		}
		held.UID = &uid
		details = fmt.Sprintf("api port %s held by uid %d (gateway uid %d)", a.addr, uid, self)
	}
	routed := routeOnlyConnectorsOf(cfg)
	fmt.Fprintf(os.Stderr, "[sidecar-api] WARNING: %s holds the API port of %s; while it does, it receives what agents and hooks send to this gateway\n", held.holder(), a.addr)
	if len(routed) > 0 && ossRouteOnlyGateway(cfg) {
		fmt.Fprintf(os.Stderr, "[sidecar-api] route-only agents (%s) send their model calls to that port: to restore direct model access until the port is back, remove them from routing.route_only.connectors in config.yaml and run defenseclaw-gateway connector route-restore --connector <name> for each; the route credential is replaced when this gateway owns the port again\n", strings.Join(routed, ", "))
		details += "; route-only connectors " + strings.Join(routed, ",") + "; route credential replaced when the port is back"
		held.At = time.Now().UTC()
		mark, _ := json.Marshal(held)
		if err := safefile.WritePrivate(filepath.Join(a.configDataDir(), "hooks", routePortHeldName), mark); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar-api] could not record the held API port: %v\n", err)
		}
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtxSeverity(context.Background(), string(audit.ActionGatewayDegraded), "api-port", details, "HIGH")
	}
	return true
}

// rotateRouteKeyAfterHeldPort runs when this gateway owns its API port. After
// another account held the port (the mark of noteAPIPortHolder), an OSS
// gateway replaces its route key before the first request: the replaced key
// is dropped at once (no pending window, DESIGN 18.4), and the agent configs
// are rendered again with the new credential (onRouteKeyRotated). Managed
// hosts rotate through the route epoch and the per-user keys instead.
func (a *APIServer) rotateRouteKeyAfterHeldPort() {
	if !ossRouteOnlyGateway(a.liveConfig()) {
		return
	}
	dataDir := a.configDataDir()
	if dataDir == "" {
		return
	}
	markPath := filepath.Join(dataDir, "hooks", routePortHeldName)
	raw, err := os.ReadFile(markPath)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var mark routePortHeld
	_ = json.Unmarshal(raw, &mark)
	if err := rotateRouteTokenKey(dataDir); err != nil {
		// The mark stays: the next start tries again.
		fmt.Fprintf(os.Stderr, "[sidecar-api] WARNING: could not replace the route credential after the API port was held: %v\n", err)
		return
	}
	if ro := a.routeOnly.Load(); ro != nil && ro.tokens != nil {
		ro.tokens.reset()
	}
	_ = os.Remove(markPath)
	fmt.Fprintf(os.Stderr, "[sidecar-api] route credential replaced: %s held the API port; the old credential is refused from now on, restart route-only agents\n", mark.holder())
	if a.logger != nil {
		_ = a.logger.LogActionCtxSeverity(context.Background(), string(audit.ActionGatewayRecovered), "api-port",
			fmt.Sprintf("api port %s owned again; route credential replaced after %s held it", a.addr, mark.holder()), "MEDIUM")
	}
	if a.onRouteKeyRotated != nil {
		a.onRouteKeyRotated()
	}
}

// rotateRouteTokenKey writes a fresh OSS route key and drops a staged one.
func rotateRouteTokenKey(dataDir string) error {
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return err
	}
	dir := filepath.Join(dataDir, "hooks")
	if err := safefile.WritePrivate(filepath.Join(dir, routeTokenKeyName), []byte(hex.EncodeToString(fresh)+"\n")); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, routeTokenNextKeyName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
