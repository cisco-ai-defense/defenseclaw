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

package sandboxreg

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// Registration keys name a registration whatever its runtime. An OpenShell
// registration's key is its id (IDPrefix and 26 base32 characters, ValidID),
// as before. An Agent Substrate actor's key carries the runtime prefix:
// "substrate:<atespace>/<actor UID>", the UID being the verified actor
// token's actorUID, so a fork (new UID) is a new registration.
//
// The per-uid FileStore keeps OpenShell ids only: ValidID is unchanged and
// refuses a prefixed key.

// SubstrateKeyPrefix is the runtime prefix of an Agent Substrate key.
const SubstrateKeyPrefix = sandboxruntime.Substrate + ":"

var (
	// substrateAtespacePattern is a Kubernetes DNS label (RFC 1123).
	substrateAtespacePattern = lazyregexp.New(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// substrateActorUIDPattern is a canonical lowercase UUID.
	substrateActorUIDPattern = lazyregexp.New(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Key is a parsed registration key.
type Key struct {
	// Runtime is sandboxruntime.OpenShell or sandboxruntime.Substrate.
	Runtime string
	// ID is the OpenShell registration id; empty for Substrate.
	ID string
	// Atespace and ActorUID name a Substrate actor; empty for OpenShell.
	Atespace string
	ActorUID string
}

// String is the key's canonical form.
func (k Key) String() string {
	if k.Runtime == sandboxruntime.Substrate {
		return SubstrateKeyPrefix + k.Atespace + "/" + k.ActorUID
	}
	return k.ID
}

// SubstrateKey is the registration key of the actor actorUID in atespace.
func SubstrateKey(atespace, actorUID string) (string, error) {
	if !substrateAtespacePattern.MatchString(atespace) {
		return "", fmt.Errorf("sandboxreg: atespace %q is not a DNS label", atespace)
	}
	if !substrateActorUIDPattern.MatchString(actorUID) {
		return "", fmt.Errorf("sandboxreg: actor UID %q is not a canonical UUID", actorUID)
	}
	return SubstrateKeyPrefix + atespace + "/" + actorUID, nil
}

// ParseKey parses an OpenShell id or a runtime-prefixed key. Only the
// canonical form parses: no case folding, spaces or other runtimes.
func ParseKey(key string) (Key, error) {
	if rest, ok := strings.CutPrefix(key, SubstrateKeyPrefix); ok {
		atespace, uid, ok := strings.Cut(rest, "/")
		if !ok {
			return Key{}, fmt.Errorf("sandboxreg: substrate key %q is not substrate:<atespace>/<actor UID>", key)
		}
		if _, err := SubstrateKey(atespace, uid); err != nil {
			return Key{}, err
		}
		return Key{Runtime: sandboxruntime.Substrate, Atespace: atespace, ActorUID: uid}, nil
	}
	if ValidID(key) {
		return Key{Runtime: sandboxruntime.OpenShell, ID: key}, nil
	}
	return Key{}, fmt.Errorf("sandboxreg: %q is not a registration key", key)
}

// ValidKey reports whether key is an OpenShell id or a Substrate key.
func ValidKey(key string) bool {
	_, err := ParseKey(key)
	return err == nil
}
