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

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// substrateRecordStoreState writes the store state ConfigMap before the
// leader serves (GAP-0081). A store newer than this build stops the leader
// (E25); any other failure is a warning, as the store itself is fine.
func substrateRecordStoreState(ctx context.Context, namespace string) error {
	if serveFlags.storeStateCM == "" {
		return nil
	}
	ca, err := os.ReadFile(serveFlags.kubeCAFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] store state not recorded: %v\n", err)
		return nil
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	kube, err := setup.NewKube("https://"+net.JoinHostPort(host, port), serveFlags.kubeTokenFile, ca)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] store state not recorded: %v\n", err)
		return nil
	}
	st, err := setup.RecordStoreState(ctx, kube, namespace, serveFlags.storeStateCM, appVersion, time.Now())
	var newer *setup.ErrStoreNewer
	if errors.As(err, &newer) {
		return err
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] store state not recorded: %v\n", err)
		return nil
	}
	fmt.Fprintf(os.Stderr, "[substrate] store schema %d recorded in %s\n", st.SchemaVersion, serveFlags.storeStateCM)
	return nil
}

// substratePolicyResetter writes admin policy_conflict resets into the
// controller's ConfigMap in this namespace (nil outside a cluster).
func substratePolicyResetter() gateway.SubstratePolicyReset {
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" || os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return nil
	}
	kube, err := setup.NewInClusterKube(setup.InClusterDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] policy reset is off: %v\n", err)
		return nil
	}
	return func(ctx context.Context, atespace, actor, by, reason string) error {
		return controller.RequestReset(ctx, kube, ns, controller.ResetRequest{Atespace: atespace, Actor: actor, By: by, Reason: reason, At: time.Now().UTC()})
	}
}
