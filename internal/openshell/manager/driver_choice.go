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

package manager

import (
	"context"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The compute driver a managed host's daemon chose for a create at sandbox
// start (openshell.SelectDriver: the user's KVM probe and the
// organization's driver_fallback). The create runs only on a gateway that
// runs that driver, and the record keeps the reason.

type driverChoiceKey struct{}

// WithDriverChoice returns ctx carrying the driver a create must run on
// and why.
func WithDriverChoice(ctx context.Context, choice openshell.DriverChoice) context.Context {
	return context.WithValue(ctx, driverChoiceKey{}, choice)
}

func driverChoiceFrom(ctx context.Context) (openshell.DriverChoice, bool) {
	choice, ok := ctx.Value(driverChoiceKey{}).(openshell.DriverChoice)
	return choice, ok && choice.Driver != ""
}

// DriverMismatchDetail is the error detail of a create refused because the
// user's OpenShell gateway runs another driver than the one chosen.
const DriverMismatchDetail = "driver_mismatch"

// driverChoiceMismatch refuses a create whose chosen driver the user's
// OpenShell gateway does not run: the gateway runs one driver for all the
// user's sandboxes, and a running sandbox never switches driver.
func driverChoiceMismatch(choice openshell.DriverChoice, running openshell.ComputeDriver) error {
	want := openshell.DriverChoiceText(string(choice.Driver), choice.Reason)
	return &sandboxapi.Error{Code: sandboxapi.CodeConflict, Status: http.StatusConflict, Detail: DriverMismatchDetail,
		Message: "this sandbox needs the " + want + " driver, but your OpenShell gateway runs the " + string(running) +
			" driver for your other sandboxes; a running sandbox never switches driver, so stop them (" +
			"defenseclaw sandbox stop NAME) and run this again"}
}
