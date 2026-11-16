// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
)

// The public receipt files (receipt-events/<receipt_id>.json, receipt.json)
// are PublicReceipt unchanged, so the closed bundle-receipt.schema.json must
// describe every member it can carry, delivery_id included.
func TestBundleReceiptSchemaDescribesEveryMember(t *testing.T) {
	contracttest.RequireMembers(t, "bundle-receipt.schema.json", reflect.TypeOf(PublicReceipt{}))
}
