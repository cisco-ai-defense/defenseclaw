// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/audit"

// persistAuditEvent routes audit events through audit.Logger when
// available so redaction, sink fanout, and OTel counters all stay
// consistent. Direct store writes remain as a fallback for tests and
// reduced wiring paths that only have the SQLite handle.
func persistAuditEvent(logger *audit.Logger, store *audit.Store, event audit.Event) error {
	if logger != nil {
		return logger.LogEvent(event)
	}
	if store != nil {
		return store.LogEvent(event)
	}
	return nil
}
