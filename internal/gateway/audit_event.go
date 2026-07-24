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

import (
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// persistAuditEvent requires the canonical logger; direct Store writes are not
// an ordinary target-runtime capability.
func persistAuditEvent(logger *audit.Logger, event audit.Event) error {
	if logger == nil {
		return errors.New("gateway: canonical audit logger unavailable")
	}
	return logger.LogEvent(event)
}

func persistAuditEventCtx(ctx context.Context, logger *audit.Logger, event audit.Event) error {
	if logger == nil {
		return errors.New("gateway: canonical audit logger unavailable")
	}
	return logger.LogEventCtx(ctx, event)
}
