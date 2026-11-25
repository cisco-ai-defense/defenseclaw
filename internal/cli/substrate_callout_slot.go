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
	"fmt"
	"io"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// substrateCalloutReader reads, from inside the cluster, who holds
// Substrate's egress callout slot (GAP-0505), for the controller: the chart
// lets the controller's ServiceAccount alone get the atenet-egress ConfigMap
// in the Substrate namespace. The gateway's create path reads the
// controller's reports from the leader instead (controller.LeaderCallout).
// Outside a pod there is no reader and the slot is not checked.
func substrateCalloutReader(sub config.SubstrateConfig, warn io.Writer) controller.CalloutReader {
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" || os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return nil
	}
	kube, err := setup.NewInClusterKube(setup.InClusterDir)
	if err != nil {
		fmt.Fprintf(warn, "warning: another egress callout replacing DefenseClaw's is not detected: %v\n", err)
		return nil
	}
	return &setup.EgressCalloutReader{Kube: kube, SubstrateNamespace: sub.SubstrateNamespace(), Namespace: ns}
}
