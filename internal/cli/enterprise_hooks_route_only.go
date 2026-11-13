// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// enterpriseHookRouteOnly is the route-only rendering the standalone
// guardian gives one protected target (S1 DESIGN 17.7): only enrolled
// users of a routed connector get one, in their own agent files, with
// their own route credential. Root and exempt_users accounts get none, so
// they keep direct model access (the gateway refuses them on /r/). nil
// when the connector is not routed, and on any error (the target then
// keeps or gets direct model access; its hooks are unaffected).
func enterpriseHookRouteOnly(connectorName, account, identity, apiAddr string) *connector.RouteOnlySetup {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	if cfg == nil || !cfg.StandaloneEnterprise() || !gateway.RouteOnlyRouted(cfg, name) {
		return nil
	}
	canonical, ok := connector.CanonicalUserScopedIdentity(identity)
	if !ok || canonical == "0" || enterpriseHookRouteOnlyExempt(cfg.Enterprise.Enrollment.ExemptUsers, account, canonical) {
		return nil
	}
	token, err := enterpriseHookRouteToken(cfg.DataDir, name, canonical)
	if err != nil {
		fmt.Fprintf(enterpriseHookRouteOnlyLog, "[hook-guardian] route-only for %s not rendered: %v\n", name, err)
		return nil
	}
	return gateway.ManagedRouteOnlySetup(cfg, name, apiAddr, token)
}

// enterpriseHookWindowsRouteOnly is enterpriseHookRouteOnly for the
// Windows guardian paths (install, verify, reconcile), which Linux and
// macOS share with the Secure Client profile; the standalone Unix guardian
// sets RouteOnly in its own worker paths. nil off Windows.
func enterpriseHookWindowsRouteOnly(connectorName, account, sid, apiAddr string) *connector.RouteOnlySetup {
	if enterpriseHookRouteOnlyGOOS != "windows" {
		return nil
	}
	return enterpriseHookRouteOnly(connectorName, account, sid, apiAddr)
}

// enterpriseHookRouteOnlyGOOS selects the Windows guardian paths;
// replaceable in tests.
var enterpriseHookRouteOnlyGOOS = runtime.GOOS

// enterpriseHookRouteOnlyLog receives the guardian route-only notes.
var enterpriseHookRouteOnlyLog io.Writer = os.Stderr

// enterpriseHookRouteToken derives the route credential the gateway
// accepts for identity: from the per-user key on Linux and macOS, and from
// the gateway route epoch on Windows (none before the gateway published
// one: it has not owned its API port yet).
var enterpriseHookRouteToken = func(dataDir, connectorName, identity string) (string, error) {
	key, err := enterpriseHookUserScopedKey(dataDir, false)
	if err != nil {
		return "", err
	}
	var epoch *connector.RouteEpoch
	if runtime.GOOS == "windows" {
		if epoch, err = connector.LoadRouteEpoch(dataDir); err != nil {
			return "", err
		}
		if epoch == nil {
			return "", errors.New("the gateway has not published its route epoch yet")
		}
	}
	return connector.ManagedRouteToken(key, epoch, connectorName, identity)
}

// enterpriseHookRouteOnlyExempt reports exempt_users naming the account by
// its name or its uid or SID (the exact forms; a directory-fact match the
// gateway also makes refuses such a caller on /r/ with 401). On Windows the
// name compares without case and without its DOMAIN\ or @domain part, as
// the gateway windowsExemptListed does, so a bare entry also skips the
// render of a domain account.
func enterpriseHookRouteOnlyExempt(entries []string, account, identity string) bool {
	account = strings.TrimSpace(account)
	windowsNames := enterpriseHookRouteOnlyGOOS == "windows"
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, identity) || (account != "" && entry == account) {
			return true
		}
		if windowsNames && account != "" {
			bare := useridentity.BareAccountName(account)
			if strings.EqualFold(entry, account) || (bare != "" && strings.EqualFold(useridentity.BareAccountName(entry), bare)) {
				return true
			}
		}
	}
	return false
}
