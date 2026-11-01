// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "github.com/defenseclaw/defenseclaw/internal/accountjoin"

// GatewayReadsCredential reports whether the gateway service is given
// stored credential name: on Linux through LoadCredential (or the secrets
// folder's group on a systemd without it), on macOS through that group,
// and on Windows through the gateway service SID's read entry on the file.
// The tenant secrets of the account join key are read only by root or an
// elevated administrator (enterprise status, verify and account-keys, and
// bundle verify and apply for their binding), never by the gateway, so the
// gateway gets no access to them (rel-1-0-6:GAP-0301).
func GatewayReadsCredential(name string) bool { return !accountjoin.IsTenantSecret(name) }
