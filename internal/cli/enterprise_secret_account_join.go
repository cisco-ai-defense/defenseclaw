// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
)

// errAccountJoinSecretMalformed refuses an account join tenant secret that
// is not 32 bytes in base64url. It never repeats the value.
var errAccountJoinSecretMalformed = errors.New("account-join-key and account-join-key-next must be 32 random bytes in base64url")

// accountJoinSecretFormatError checks a value `enterprise secret set`
// stores under the account join names; every other name passes.
func accountJoinSecretFormatError(name string, value []byte) error {
	if name != accountjoin.SecretName && name != accountjoin.NextSecretName {
		return nil
	}
	secret, err := accountjoin.ParseSecret(value)
	clear(secret)
	if err != nil {
		return errAccountJoinSecretMalformed
	}
	return nil
}
