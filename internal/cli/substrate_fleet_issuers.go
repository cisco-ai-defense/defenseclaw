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
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// fleetContextsNone is the --fleet-contexts value that reads this cluster only.
const fleetContextsNone = "none"

// otherClusterTimeout bounds the read of one other cluster, so a context
// whose API server is gone does not hold verify up.
const otherClusterTimeout = 8 * time.Second

// otherClusterReaders is how many other clusters are read at once.
const otherClusterReaders = 8

// readOtherClusters fills o.Clusters, o.OtherIssuers and o.FleetUnread for
// issuer_unique (E13, GAP-0383). The other clusters are the ones the
// administrator's kubeconfig reaches: every other context, or the contexts
// --fleet-contexts names. Contexts of one API server count once. A cluster
// counts when DefenseClaw runs in it (the chart's defenseclaw-config
// ConfigMap with a substrate section, in any namespace, else in --namespace),
// and its substrate.identity.issuer is compared with this cluster's. A
// cluster that does not answer is counted in FleetUnread.
func readOtherClusters(ctx context.Context, f *substrateClusterFlags, o *fleet.Observed, current string) {
	o.Clusters = 1
	if len(f.fleetContexts) == 1 && strings.EqualFold(strings.TrimSpace(f.fleetContexts[0]), fleetContextsNone) {
		return
	}
	raw, err := substrateKubectl(ctx, f, "config", "view", "-o", "json")
	if err != nil {
		// The kubeconfig named the current context a moment ago; without
		// its contexts there is nothing more to compare with.
		o.FleetUnread = len(f.fleetContexts)
		return
	}
	var kc struct {
		Contexts []struct {
			Name    string `json:"name"`
			Context struct {
				Cluster string `json:"cluster"`
			} `json:"context"`
		} `json:"contexts"`
		Clusters []struct {
			Name    string `json:"name"`
			Cluster struct {
				Server string `json:"server"`
			} `json:"cluster"`
		} `json:"clusters"`
	}
	if json.Unmarshal(raw, &kc) != nil {
		o.FleetUnread = len(f.fleetContexts)
		return
	}
	servers := map[string]string{}
	for _, c := range kc.Clusters {
		servers[c.Name] = strings.TrimRight(c.Cluster.Server, "/")
	}
	clusterOf := map[string]string{}
	for _, c := range kc.Contexts {
		key := servers[c.Context.Cluster]
		if key == "" {
			key = "cluster:" + c.Context.Cluster
		}
		clusterOf[c.Name] = key
	}
	names := f.fleetContexts
	if len(names) == 0 {
		for _, c := range kc.Contexts {
			names = append(names, c.Name)
		}
	}
	seen := []string{clusterOf[current]}
	var targets []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || n == current {
			continue
		}
		key, ok := clusterOf[n]
		if !ok {
			o.FleetUnread++ // named with --fleet-contexts, not in the kubeconfig
			continue
		}
		if slices.Contains(seen, key) {
			continue
		}
		seen = append(seen, key)
		targets = append(targets, n)
	}
	type reading struct {
		runs   bool
		issuer string
		failed bool
	}
	got := make([]reading, len(targets))
	sem := make(chan struct{}, otherClusterReaders)
	var wg sync.WaitGroup
	for i, name := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			of := *f
			of.kubeContext = name
			cctx, cancel := context.WithTimeout(ctx, otherClusterTimeout)
			defer cancel()
			text, err := otherClusterConfig(cctx, &of)
			switch {
			case err != nil:
				got[i].failed = true
			case text != "":
				got[i] = reading{runs: true, issuer: configIssuer(text)}
			}
		}()
	}
	wg.Wait()
	for _, g := range got {
		switch {
		case g.failed:
			o.FleetUnread++
		case g.runs:
			o.Clusters++
			if g.issuer != "" {
				o.OtherIssuers = append(o.OtherIssuers, g.issuer)
			}
		}
	}
}

// otherClusterConfig is DefenseClaw's config.yaml in the cluster of f's
// context, "" when DefenseClaw does not run there. It looks in every
// namespace first (the other install may use another one), then in
// --namespace when the identity may not list ConfigMaps cluster-wide.
func otherClusterConfig(ctx context.Context, f *substrateClusterFlags) (string, error) {
	items, err := kubeGetList(ctx, f, "get", "configmaps", "-A", "-l", "app.kubernetes.io/name=defenseclaw-substrate",
		"--field-selector", "metadata.name=defenseclaw-config")
	if err != nil {
		if items, err = kubeGetList(ctx, f, "get", "configmaps", "-n", f.namespace); err != nil {
			return "", err
		}
	}
	for _, c := range items {
		if t := c.Data["config.yaml"]; strings.Contains(t, "substrate:") {
			return t, nil
		}
	}
	return "", nil
}

// configIssuer is substrate.identity.issuer of a DefenseClaw config.yaml.
func configIssuer(text string) string {
	var doc struct {
		Substrate struct {
			Identity struct {
				Issuer string `yaml:"issuer"`
			} `yaml:"identity"`
		} `yaml:"substrate"`
	}
	if yaml.Unmarshal([]byte(text), &doc) != nil {
		return ""
	}
	return strings.TrimSpace(doc.Substrate.Identity.Issuer)
}
