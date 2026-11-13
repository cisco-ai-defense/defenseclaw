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
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// routePortHeldName marks, under <dataDir>/hooks, that another account held
// the API port of this OSS gateway while route-only was on. The route key is
// replaced once the gateway owns the port again (S1 DESIGN 17.1, 18.4);
// doctor reports the mark until then.
const routePortHeldName = ".route-port-held.json"

type routePortHeld struct {
	UID  int       `json:"uid"`
	Addr string    `json:"addr"`
	At   time.Time `json:"at"`
}

// apiPortSelfUID is the account this gateway runs as; replaceable in tests.
var apiPortSelfUID = os.Getuid

// routeOnlyConnectorsOf lists the route-only connectors config.yaml routes.
func routeOnlyConnectorsOf(cfg *config.Config) []string {
	if cfg == nil || !cfg.Routing.Enabled {
		return nil
	}
	return cfg.Routing.RouteOnly.Connectors
}

// noteAPIPortHolder runs at the first bind of the API address that found it
// held. On Linux it reads which account holds the port (/proc/net/tcp and
// tcp6); another account is audited (gateway-degraded, HIGH) and named on
// stderr with the advice to turn route-only off until the port is back. The
// route credential is not rotated now: whoever holds the port would get the
// new one too. It is replaced when this gateway owns the port again
// (rotateRouteKeyAfterHeldPort).
func (a *APIServer) noteAPIPortHolder() {
	self := apiPortSelfUID()
	uid, found, err := apiPortHolderUID(a.addr, self)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] could not read which account holds %s: %v\n", a.addr, err)
		return
	}
	if !found || uid == self {
		return
	}
	cfg := a.liveConfig()
	routed := routeOnlyConnectorsOf(cfg)
	fmt.Fprintf(os.Stderr, "[sidecar-api] WARNING: another account (uid %d) holds the API port of %s; while it does, it receives what agents and hooks send to this gateway\n", uid, a.addr)
	details := fmt.Sprintf("api port %s held by uid %d (gateway uid %d)", a.addr, uid, self)
	if len(routed) > 0 && (cfg == nil || !cfg.StandaloneEnterprise()) {
		fmt.Fprintf(os.Stderr, "[sidecar-api] route-only agents (%s) send their model calls to that port: run defenseclaw routing disable --connector <name> for each until the port is back; the route credential is replaced when this gateway owns the port again\n", strings.Join(routed, ", "))
		details += "; route-only connectors " + strings.Join(routed, ",") + "; route credential replaced when the port is back"
		mark, _ := json.Marshal(routePortHeld{UID: uid, Addr: a.addr, At: time.Now().UTC()})
		if err := safefile.WritePrivate(filepath.Join(a.configDataDir(), "hooks", routePortHeldName), mark); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar-api] could not record the held API port: %v\n", err)
		}
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtxSeverity(context.Background(), string(audit.ActionGatewayDegraded), "api-port", details, "HIGH")
	}
}

// rotateRouteKeyAfterHeldPort runs when this gateway owns its API port. After
// another account held the port (the mark of noteAPIPortHolder), an OSS
// gateway replaces its route key before the first request: the replaced key
// is dropped at once (no pending window, DESIGN 18.4), and the agent configs
// are rendered again with the new credential (onRouteKeyRotated). Managed
// hosts rotate through the route epoch and the per-user keys instead.
func (a *APIServer) rotateRouteKeyAfterHeldPort() {
	if a.userScopedCredentialsRequired() {
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
	fmt.Fprintf(os.Stderr, "[sidecar-api] route credential replaced: another account (uid %d) held the API port; the old credential is refused from now on, restart route-only agents\n", mark.UID)
	if a.logger != nil {
		_ = a.logger.LogActionCtxSeverity(context.Background(), string(audit.ActionGatewayRecovered), "api-port",
			fmt.Sprintf("api port %s owned again; route credential replaced after uid %d held it", a.addr, mark.UID), "MEDIUM")
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
