// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Route credentials on a managed (standalone) gateway (S1 DESIGN 16.9, 17.2,
// 19). The guardian renders one per enrolled user into that user agent
// files (X-DC-Route-Auth); the gateway derives the same values for every
// protected target of its ledger, like the hook and OTLP credentials.
//
// On Linux and macOS the route credential derives from the per-user
// credential key itself (kind "route"), so it follows the lifecycle key
// rotation (.next/.prev). Windows has no such rotation, so there the
// gateway owns a route epoch (RouteEpoch): a fresh random value it writes
// each time it owns its API port again, plus a per-account generation it
// bumps when an enrollment that ended comes back. The route key of an
// account is HMAC(per-user key, epoch, generation), so a credential
// captured while another account held the port (a gateway restart) or
// before an enrollment ended stops authenticating at once.

// UserScopedRouteCredential authenticates a route-only caller.
const UserScopedRouteCredential = "route"

// UserScopedRouteToken derives the route credential of one user for one
// connector from key (the per-user credential key, or a RouteEpoch key).
func UserScopedRouteToken(key, connectorName, identity string) (string, error) {
	scope, err := normalizeHookAPITokenScope(connectorName)
	if err != nil {
		return "", err
	}
	return deriveUserScopedToken(key, UserScopedRouteCredential, scope, identity)
}

// RouteEpoch is the gateway-owned route rotation state of a managed Windows
// gateway. It is not secret (the per-user key is); it lives beside the keys
// in the gateway hooks directory, which only the gateway service and
// administrators can write.
type RouteEpoch struct {
	Version int `json:"version"`
	// Epoch is 64 lowercase hex characters, new each time the gateway owns
	// its API port.
	Epoch string `json:"epoch"`
	// Generations counts, per canonical identity (SID or uid), the
	// enrollments that came back under this epoch.
	Generations map[string]int `json:"generations,omitempty"`
}

const (
	routeEpochFileName = "route-epoch.json"
	routeEpochDomain   = "defenseclaw.route-epoch.v1"
	routeEpochVersion  = 1
	routeEpochMaxBytes = 1 << 20
)

// RouteEpochPath is where the gateway publishes its route epoch.
func RouteEpochPath(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("RouteEpochPath: empty dataDir")
	}
	return filepath.Join(dataDir, "hooks", routeEpochFileName), nil
}

// NewRouteEpoch returns a fresh epoch with no generations.
func NewRouteEpoch() (RouteEpoch, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return RouteEpoch{}, err
	}
	return RouteEpoch{Version: routeEpochVersion, Epoch: hex.EncodeToString(raw), Generations: map[string]int{}}, nil
}

// Validate checks the shape of an epoch read from disk.
func (e RouteEpoch) Validate() error {
	if e.Version != routeEpochVersion {
		return fmt.Errorf("route epoch version %d is not %d", e.Version, routeEpochVersion)
	}
	if !otlpTokenHexRE.MatchString(e.Epoch) {
		return errors.New("route epoch is not 64 lowercase hex characters")
	}
	for identity, generation := range e.Generations {
		canonical, ok := CanonicalUserScopedIdentity(identity)
		if !ok || canonical != identity || generation < 0 {
			return fmt.Errorf("route epoch generation entry %q is not valid", identity)
		}
	}
	return nil
}

// RouteKey is the key the route credentials of identity derive from: key
// itself without an epoch (Linux, macOS), else HMAC(key, epoch, generation).
func (e *RouteEpoch) RouteKey(key, identity string) (string, error) {
	if e == nil {
		return key, nil
	}
	canonical, ok := CanonicalUserScopedIdentity(identity)
	if !ok {
		return "", fmt.Errorf("route epoch identity %q is neither a uid nor a SID", identity)
	}
	key = strings.TrimSpace(key)
	if !otlpTokenHexRE.MatchString(key) {
		return "", errors.New("per-user credential key is not a 64-character lowercase hex secret")
	}
	secret, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(routeEpochDomain + "\x00" + e.Epoch + "\x00" + canonical + "\x00" + strconv.Itoa(e.Generations[canonical])))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ManagedRouteToken is the route credential the guardian renders for
// identity under the per-user key and the gateway epoch (nil off Windows).
func ManagedRouteToken(key string, epoch *RouteEpoch, connectorName, identity string) (string, error) {
	routeKey, err := epoch.RouteKey(key, identity)
	if err != nil {
		return "", err
	}
	return UserScopedRouteToken(routeKey, connectorName, identity)
}

// LoadRouteEpoch reads the published epoch; nil and no error when the
// gateway has not published one yet (it has not owned its port).
func LoadRouteEpoch(dataDir string) (*RouteEpoch, error) {
	path, err := RouteEpochPath(dataDir)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > routeEpochMaxBytes {
		return nil, fmt.Errorf("route epoch %s is not a small regular file", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var epoch RouteEpoch
	if err := json.Unmarshal(raw, &epoch); err != nil {
		return nil, fmt.Errorf("route epoch %s: %w", path, err)
	}
	if err := epoch.Validate(); err != nil {
		return nil, fmt.Errorf("route epoch %s: %w", path, err)
	}
	return &epoch, nil
}

// WriteRouteEpoch publishes epoch atomically (temp file + rename).
func WriteRouteEpoch(dataDir string, epoch RouteEpoch) error {
	if err := epoch.Validate(); err != nil {
		return err
	}
	path, err := RouteEpochPath(dataDir)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(epoch)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".route-epoch-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
