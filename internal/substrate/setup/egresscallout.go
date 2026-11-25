// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Who holds Substrate's one additional egress callout, read from the live
// atenet-egress Envoy config rather than from a SubstrateInstall file: a
// file can be stale, and ate-setup deploy with another file replaces the
// DefenseClaw callout without DefenseClaw hearing of it (GAP-0505).
const (
	// EgressConfigMap is the ConfigMap in the Substrate namespace that
	// holds atenet-egress's Envoy config (key EgressEnvoyKey). The chart
	// lets the controller's ServiceAccount alone get this one ConfigMap and
	// nothing else there; the gateway reads the controller's result through
	// the leader (GAP-0505).
	EgressConfigMap = "atenet-egress"
	EgressEnvoyKey  = "envoy.yaml"
	// egressCalloutCluster is the Envoy cluster ate-setup renders for
	// atenet.egress.additionalExtprocService (Substrate 1.0.x); without a
	// registered callout the config has no such cluster.
	egressCalloutCluster = "additional_egress_ext_proc"
)

// CalloutSlot is who holds the egress callout slot.
type CalloutSlot struct {
	// Holder is the callout egress sends requests to, NS/SVC:PORT like
	// additionalExtprocService ("" when no callout is registered).
	Holder string
	// Ours reports that Holder is the DefenseClaw callout of the release
	// namespace (any port).
	Ours bool
}

// IsDefenseClawCallout reports whether service (NS/SVC:PORT) is the
// DefenseClaw callout of namespace, on any port.
func IsDefenseClawCallout(service, namespace string) bool {
	return namespace != "" && isOurCallout(service, namespace)
}

// ConfigMapGetter reads one ConfigMap; not found is (nil, nil) (Kube).
type ConfigMapGetter interface {
	GetConfigMap(ctx context.Context, namespace, name string) (*ConfigMap, error)
}

// EgressCalloutReader reads the callout slot from the cluster.
type EgressCalloutReader struct {
	Kube ConfigMapGetter
	// SubstrateNamespace is where atenet-egress runs; Namespace is the
	// DefenseClaw release namespace (the callout DefenseClaw deploys).
	SubstrateNamespace string
	Namespace          string
}

// ReadCalloutSlot reads atenet-egress's config now. An error means the slot
// is not known (no grant, no ConfigMap, a config this release cannot read).
func (r *EgressCalloutReader) ReadCalloutSlot(ctx context.Context) (CalloutSlot, error) {
	if r == nil || r.Kube == nil {
		return CalloutSlot{}, errors.New("no Kubernetes client")
	}
	ns := r.SubstrateNamespace
	if ns == "" {
		ns = "ate-system"
	}
	cm, err := r.Kube.GetConfigMap(ctx, ns, EgressConfigMap)
	if err != nil {
		return CalloutSlot{}, fmt.Errorf("read ConfigMap %s/%s: %w", ns, EgressConfigMap, err)
	}
	if cm == nil {
		return CalloutSlot{}, fmt.Errorf("ConfigMap %s/%s does not exist", ns, EgressConfigMap)
	}
	raw, ok := cm.Data[EgressEnvoyKey]
	if !ok {
		return CalloutSlot{}, fmt.Errorf("ConfigMap %s/%s has no %s", ns, EgressConfigMap, EgressEnvoyKey)
	}
	holder, err := EgressCalloutHolder([]byte(raw))
	if err != nil {
		return CalloutSlot{}, err
	}
	return CalloutSlot{Holder: holder, Ours: IsDefenseClawCallout(holder, r.Namespace)}, nil
}

// EgressCalloutHolder returns the callout an atenet-egress Envoy config
// sends requests to, NS/SVC:PORT ("" when it has none). An address that is
// not a Service name is returned as HOST:PORT.
func EgressCalloutHolder(envoyYAML []byte) (string, error) {
	var doc any
	if err := yaml.Unmarshal(envoyYAML, &doc); err != nil {
		return "", fmt.Errorf("atenet-egress %s: %w", EgressEnvoyKey, err)
	}
	if doc == nil {
		return "", fmt.Errorf("atenet-egress %s is empty", EgressEnvoyKey)
	}
	cluster := findNamed(doc, egressCalloutCluster, 0)
	if cluster == nil {
		return "", nil
	}
	host, port := calloutEndpoint(cluster)
	if host == "" {
		return "", fmt.Errorf("atenet-egress %s: the %s cluster names no endpoint", EgressEnvoyKey, egressCalloutCluster)
	}
	return serviceRef(host, port), nil
}

// findNamed returns the first mapping (depth first) whose name is name and
// that has a load_assignment: an Envoy cluster.
func findNamed(node any, name string, depth int) map[string]any {
	if depth > 64 {
		return nil
	}
	switch n := node.(type) {
	case map[string]any:
		if s, _ := n["name"].(string); s == name {
			if _, ok := n["load_assignment"]; ok {
				return n
			}
		}
		for _, v := range n {
			if m := findNamed(v, name, depth+1); m != nil {
				return m
			}
		}
	case []any:
		for _, v := range n {
			if m := findNamed(v, name, depth+1); m != nil {
				return m
			}
		}
	}
	return nil
}

// calloutEndpoint is the first endpoint of a cluster's load_assignment.
func calloutEndpoint(cluster map[string]any) (string, int) {
	la, _ := cluster["load_assignment"].(map[string]any)
	eps, _ := la["endpoints"].([]any)
	for _, e := range eps {
		em, _ := e.(map[string]any)
		lbs, _ := em["lb_endpoints"].([]any)
		for _, lb := range lbs {
			lm, _ := lb.(map[string]any)
			ep, _ := lm["endpoint"].(map[string]any)
			addr, _ := ep["address"].(map[string]any)
			sa, _ := addr["socket_address"].(map[string]any)
			host, _ := sa["address"].(string)
			if host = strings.TrimSpace(host); host == "" {
				continue
			}
			port := 0
			switch p := sa["port_value"].(type) {
			case int:
				port = p
			case string:
				port, _ = strconv.Atoi(p)
			}
			return host, port
		}
	}
	return "", 0
}

// serviceRef turns svc.ns.svc[.cluster.local] and a port into NS/SVC:PORT.
func serviceRef(host string, port int) string {
	h := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(host, "."), ".cluster.local"), ".svc")
	if parts := strings.Split(h, "."); len(parts) == 2 && parts[0] != "" && parts[1] != "" && h != host {
		return fmt.Sprintf("%s/%s:%d", parts[1], parts[0], port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
