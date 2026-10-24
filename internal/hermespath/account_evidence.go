// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermespath

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// homeEvidence is one place that sets the Hermes home a process of the
// account can start with: home is the absolute home it names, or "" when
// the value cannot be resolved without running the account's shell.
type homeEvidence struct {
	source string
	home   string
}

// VerifyAccountHome fails when anything the account at userHome starts its
// processes with names a Hermes home other than home, or sets HERMES_HOME
// to a value a service cannot resolve: then a check of home does not prove
// which home the account's Hermes reads (GAP-0499). It reads the redirects
// DefenseClaw's hooks recorded in the account's foreign-hook-env.json and,
// on Linux and macOS, the environment files the sign-in reads
// (environment.d, pam_environment, /etc/environment), the shell startup
// files, the account's launchd environment on macOS and the environment of
// the environment of its running processes. Evidence it cannot read fails
// too. setUpAt is when Setup last registered the hooks in home (zero when
// unknown): a recorded redirect last seen RecordRefreshInterval or more
// before it no longer counts, because a hook that ran with it since would
// have refreshed it.
func VerifyAccountHome(userHome, home string, setUpAt time.Time) error {
	userHome = strings.TrimSpace(userHome)
	if userHome == "" || !filepath.IsAbs(userHome) {
		return errors.New("HERMES_HOME unproven: the account home is not absolute")
	}
	evidence, err := recordedHomeEvidence(userHome, setUpAt)
	if err != nil {
		return fmt.Errorf("HERMES_HOME unproven: %w", err)
	}
	platform, err := accountEnvironmentEvidence(userHome)
	if err != nil {
		return fmt.Errorf("HERMES_HOME unproven: %w", err)
	}
	for _, found := range append(evidence, platform...) {
		if found.home == "" {
			return fmt.Errorf("HERMES_HOME unproven: %s sets HERMES_HOME to a value a service cannot resolve", found.source)
		}
		if !sameHome(found.home, home) {
			return fmt.Errorf("HERMES_HOME unproven: %s names the Hermes home %s, not %s", found.source, found.home, home)
		}
	}
	return nil
}

// envRedirectRecord is the part of the redirect record DefenseClaw's hooks
// keep in the account's data directory (enterprisepolicy.RecordEnvRedirect)
// that names Hermes homes.
type envRedirectRecord struct {
	Connectors map[string][]struct {
		Homes []string          `json:"homes"`
		Vars  map[string]string `json:"vars"`
		Seen  string            `json:"seen"`
	} `json:"connectors"`
}

// envRedirectRecordLimit bounds the record read, as its writer does.
const envRedirectRecordLimit = 64 << 10

// RecordRefreshInterval is how long a hook leaves a recorded redirect it
// sees again before it records the new sighting
// (enterprisepolicy.RecordEnvRedirect).
const RecordRefreshInterval = 24 * time.Hour

// supersededRedirect reports whether a redirect last seen at seen predates
// the Setup at setUpAt by RecordRefreshInterval or more: a hook that ran
// with it after that Setup would have refreshed seen, so no agent has. A
// redirect with no readable time is current.
func supersededRedirect(seen string, setUpAt time.Time) bool {
	at, err := time.Parse(time.RFC3339, seen)
	return err == nil && !setUpAt.IsZero() && setUpAt.Sub(at) >= RecordRefreshInterval
}

// recordedHomeEvidence returns the Hermes homes DefenseClaw hooks saw the
// account's agents run with: a HERMES_HOME any of them recorded, and a HOME
// the Hermes hook ran with (Hermes then reads its .hermes on Linux and
// macOS), except a redirect the Setup at setUpAt superseded
// (supersededRedirect). A record that cannot be read fails.
func recordedHomeEvidence(userHome string, setUpAt time.Time) ([]homeEvidence, error) {
	path := filepath.Join(userHome, ".defenseclaw", "foreign-hook-env.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > envRedirectRecordLimit {
		return nil, fmt.Errorf("%s is not a bounded regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var record envRedirectRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	names := make([]string, 0, len(record.Connectors))
	for name := range record.Connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	source := "a HERMES_HOME the DefenseClaw hooks recorded in " + path
	var out []homeEvidence
	for _, name := range names {
		for _, redirect := range record.Connectors[name] {
			if supersededRedirect(redirect.Seen, setUpAt) {
				continue
			}
			if value, ok := redirect.Vars["HERMES_HOME"]; ok {
				out = append(out, homeEvidence{source: source, home: absoluteHome(value)})
				continue
			}
			if name != "hermes" || runtime.GOOS == "windows" {
				continue
			}
			for _, home := range redirect.Homes {
				if home = absoluteHome(home); home != "" {
					out = append(out, homeEvidence{source: "a HOME the Hermes hook recorded in " + path, home: filepath.Join(home, ".hermes")})
				}
			}
		}
	}
	return out, nil
}

// absoluteHome is value as an absolute clean path, or "".
func absoluteHome(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) {
		return ""
	}
	return filepath.Clean(value)
}

func sameHome(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
