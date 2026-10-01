// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package unixidentity resolves local and directory-backed Unix accounts for
// the enterprise hook guardian and enumerator.
//
// The release binaries are built with CGO_ENABLED=0. On Linux that means
// os/user only reads /etc/passwd and /etc/group, so LDAP, SSSD, AD, NIS and
// systemd-userdb accounts are invisible to it. This package asks NSS through
// the root-owned getent binary instead. On macOS os/user already goes through
// libSystem (Open Directory), so the resolver delegates to it and only uses
// dscl to list local accounts.
//
// A lookup error is never a deletion signal. Only ErrNotFound — a definitive
// "no such entry" answer from NSS or Directory Services — means an account
// is absent; every other error is a transient directory failure that callers
// must treat as "unknown, retry later".
//
// The package is Unix-only; on Windows it contains no code.
package unixidentity
