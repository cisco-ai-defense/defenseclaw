// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"time"
)

// enterprise.account_join modes. Absent is off.
const (
	AccountJoinOn  = "on"
	AccountJoinOff = "off"
	// AccountJoinMinProductVersion is the first release that reads
	// enterprise.account_join; a bundle that sets it needs this floor.
	AccountJoinMinProductVersion = "1.0.7"
	// accountJoinMaxGeneration bounds a generation number.
	accountJoinMaxGeneration = 1<<31 - 1
)

// EnterpriseAccountJoinConfig is enterprise.account_join (standalone only):
// whether the root-only status reports the account join key of each
// account that ran an agent (internal/accountjoin), and which generation
// each stored tenant secret is. The secrets themselves are the protected
// credentials account-join-key and account-join-key-next.
type EnterpriseAccountJoinConfig struct {
	// Mode is on or off ("" = off).
	Mode string `mapstructure:"mode" yaml:"mode,omitempty"`
	// Generation numbers the secret in account-join-key (1 or more when on),
	// and SecretSHA256 is the SHA-256 (lowercase hex) of its stored value:
	// a device whose stored secret has another digest reports no key of
	// the generation (secret_mismatch).
	Generation   int    `mapstructure:"generation" yaml:"generation,omitempty"`
	SecretSHA256 string `mapstructure:"secret_sha256" yaml:"secret_sha256,omitempty"`
	// NextGeneration numbers the secret in account-join-key-next while a
	// rotation overlaps (0 = none), and NextNotAfter (RFC 3339) is when the
	// device stops reporting it, at most 30 days ahead.
	NextGeneration   int    `mapstructure:"next_generation" yaml:"next_generation,omitempty"`
	NextSecretSHA256 string `mapstructure:"next_secret_sha256" yaml:"next_secret_sha256,omitempty"`
	NextNotAfter     string `mapstructure:"next_not_after" yaml:"next_not_after,omitempty"`
}

// On reports enterprise.account_join.mode on.
func (c EnterpriseAccountJoinConfig) On() bool {
	return strings.TrimSpace(c.Mode) == AccountJoinOn
}

// NextNotAfterTime parses NextNotAfter (zero when unset or invalid).
func (c EnterpriseAccountJoinConfig) NextNotAfterTime() time.Time {
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(c.NextNotAfter))
	if err != nil {
		return time.Time{}
	}
	return at
}

func accountJoinEmpty(c EnterpriseAccountJoinConfig) bool {
	return c == EnterpriseAccountJoinConfig{}
}

// validateAccountJoin checks enterprise.account_join.
func validateAccountJoin(c EnterpriseAccountJoinConfig) error {
	switch strings.TrimSpace(c.Mode) {
	case "", AccountJoinOff, AccountJoinOn:
	default:
		return fmt.Errorf("config: enterprise.account_join.mode %q must be on or off", c.Mode)
	}
	if c.Generation < 0 || c.Generation > accountJoinMaxGeneration || c.NextGeneration < 0 || c.NextGeneration > accountJoinMaxGeneration {
		return fmt.Errorf("config: enterprise.account_join generations must be between 0 and %d", accountJoinMaxGeneration)
	}
	if c.On() && c.Generation < 1 {
		return fmt.Errorf("config: enterprise.account_join.generation must be 1 or more when mode is on")
	}
	if c.On() && !accountJoinSHA256(c.SecretSHA256) {
		return fmt.Errorf("config: enterprise.account_join.secret_sha256 must be the SHA-256 (64 lowercase hex digits) of the account-join-key value when mode is on")
	}
	if c.SecretSHA256 != "" && !accountJoinSHA256(c.SecretSHA256) || c.NextSecretSHA256 != "" && !accountJoinSHA256(c.NextSecretSHA256) {
		return fmt.Errorf("config: enterprise.account_join secret digests must be 64 lowercase hex digits")
	}
	if c.NextGeneration != 0 && !accountJoinSHA256(c.NextSecretSHA256) {
		return fmt.Errorf("config: enterprise.account_join.next_secret_sha256 must be set with next_generation")
	}
	if c.NextGeneration != 0 && c.NextGeneration <= c.Generation {
		return fmt.Errorf("config: enterprise.account_join.next_generation must be above generation")
	}
	if (c.NextGeneration != 0) != (strings.TrimSpace(c.NextNotAfter) != "") {
		return fmt.Errorf("config: enterprise.account_join.next_generation and next_not_after are set together")
	}
	if strings.TrimSpace(c.NextNotAfter) != "" && c.NextNotAfterTime().IsZero() {
		return fmt.Errorf("config: enterprise.account_join.next_not_after must be an RFC 3339 time")
	}
	return nil
}

func accountJoinSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// UsesMinProductVersion107Keys lists the keys cfg sets that only 1.0.7 and
// later read.
func (c *Config) UsesMinProductVersion107Keys() []string {
	if c == nil || accountJoinEmpty(c.Enterprise.AccountJoin) {
		return nil
	}
	return []string{"enterprise.account_join"}
}
