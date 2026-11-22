// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// hookEvents is the helm.sh/hook annotation of o, nil for a plain object.
func hookEvents(o k8sObject) []string {
	h, _ := dig(o.Metadata, "annotations", "helm.sh/hook").(string)
	if h == "" {
		return nil
	}
	var ev []string
	for _, e := range strings.Split(h, ",") {
		ev = append(ev, strings.TrimSpace(e))
	}
	return ev
}

func hookWeight(t *testing.T, o k8sObject) int {
	t.Helper()
	w, _ := dig(o.Metadata, "annotations", "helm.sh/hook-weight").(string)
	if w == "" {
		return 0
	}
	n, err := strconv.Atoi(w)
	if err != nil {
		t.Fatalf("%s/%v: hook weight %q", o.Kind, o.Metadata["name"], w)
	}
	return n
}

// readyFor says whether o exists when a hook of event runs at weight. A plain
// object of the release exists only once its resources are applied: never
// for a pre-install hook, and never in Argo CD's PreSync phase, where Argo
// CD runs every pre-install and pre-upgrade hook, on a first sync too. A hook
// object exists for its own events, when its weight is below the Job's.
func readyFor(t *testing.T, o k8sObject, event string, weight int) error {
	ev := hookEvents(o)
	if ev == nil {
		if event == "pre-install" || event == "pre-upgrade" {
			return fmt.Errorf("a plain object, created after the %s hooks (Argo CD: in Sync, after PreSync)", event)
		}
		return nil
	}
	if !slices.Contains(ev, event) {
		return fmt.Errorf("a hook of %v only, not of %s", ev, event)
	}
	if w := hookWeight(t, o); w >= weight {
		return fmt.Errorf("hook weight %d, not below the Job's %d", w, weight)
	}
	return nil
}

// GAP-0459: under Argo CD the pre-upgrade hook Job ran in PreSync on a first
// sync, and its ServiceAccount, Role and RoleBinding were plain objects of
// the Sync phase, so the Job never started and the sync waited forever.
// Every hook Job finds what it runs with already there, for each of its
// events, under helm install, upgrade, rollback and uninstall and under Argo
// CD: its ServiceAccount, every RoleBinding of that account (and its Role)
// that is meant for the event, and every ConfigMap or Secret of the chart it
// mounts.
func TestChartHookJobsFindTheirAccountsAndGrantsFirst(t *testing.T) {
	helm := helmBinary(t)
	for _, c := range chartCases {
		t.Run(c, func(t *testing.T) {
			objs := decodeObjects(t, renderChart(t, helm, c))
			byName := map[string]k8sObject{}
			for _, o := range objs {
				ns, _ := o.Metadata["namespace"].(string)
				byName[o.Kind+"/"+ns+"/"+o.Metadata["name"].(string)] = o
			}
			get := func(kind, ns, name string) (k8sObject, bool) {
				if o, ok := byName[kind+"/"+ns+"/"+name]; ok {
					return o, true
				}
				if ns == "defenseclaw-system" {
					o, ok := byName[kind+"//"+name]
					return o, ok
				}
				return k8sObject{}, false
			}
			jobs := 0
			for _, job := range objs {
				events := hookEvents(job)
				if job.Kind != "Job" || events == nil {
					continue
				}
				jobs++
				jw := hookWeight(t, job)
				pod := dig(job.Spec, "template", "spec")
				sa, _ := dig(pod, "serviceAccountName").(string)
				saObj, ok := get("ServiceAccount", "defenseclaw-system", sa)
				if !ok {
					t.Errorf("hook Job %v runs as ServiceAccount %q, which the chart does not render", job.Metadata["name"], sa)
					continue
				}
				// The account's RoleBindings, wherever they are, and their Roles.
				type grant struct{ binding, role k8sObject }
				var grants []grant
				for _, b := range objs {
					if b.Kind != "RoleBinding" {
						continue
					}
					bound := slices.ContainsFunc(b.Subjects, func(s any) bool {
						return dig(s, "kind") == "ServiceAccount" && dig(s, "name") == sa && dig(s, "namespace") == "defenseclaw-system"
					})
					if !bound {
						continue
					}
					ns, _ := b.Metadata["namespace"].(string)
					if ns == "" {
						ns = "defenseclaw-system"
					}
					role, ok := get("Role", ns, fmt.Sprint(b.RoleRef["name"]))
					if b.RoleRef["kind"] != "Role" || !ok {
						t.Errorf("RoleBinding %v of %s binds %v %v, which the chart does not render", b.Metadata["name"], sa, b.RoleRef["kind"], b.RoleRef["name"])
						continue
					}
					grants = append(grants, grant{b, role})
				}
				// The chart ConfigMaps and Secrets the Job mounts.
				var mounts []k8sObject
				for _, v := range asList(dig(pod, "volumes")) {
					refs := []any{dig(v, "configMap"), dig(v, "secret")}
					for _, src := range asList(dig(v, "projected", "sources")) {
						refs = append(refs, dig(src, "configMap"), dig(src, "secret"))
					}
					for i, r := range refs {
						if r == nil {
							continue
						}
						kind, key := "ConfigMap", "name"
						if i%2 == 1 {
							kind = "Secret"
						}
						if i == 1 {
							key = "secretName" // a secret volume; a projected one has name
						}
						if o, ok := get(kind, "defenseclaw-system", fmt.Sprint(dig(r, key))); ok {
							mounts = append(mounts, o)
						}
					}
				}
				for _, ev := range events {
					if err := readyFor(t, saObj, ev, jw); err != nil {
						t.Errorf("hook Job %v (%s): its ServiceAccount %s is %v", job.Metadata["name"], ev, sa, err)
					}
					for _, g := range grants {
						// A binding of the account for other events only is
						// not this Job's grant.
						if be := hookEvents(g.binding); be != nil && !slices.Contains(be, ev) {
							continue
						}
						for _, o := range []k8sObject{g.binding, g.role} {
							if err := readyFor(t, o, ev, jw); err != nil {
								t.Errorf("hook Job %v (%s): %s %v of %s is %v", job.Metadata["name"], ev, o.Kind, o.Metadata["name"], sa, err)
							}
						}
					}
					for _, o := range mounts {
						if err := readyFor(t, o, ev, jw); err != nil {
							t.Errorf("hook Job %v (%s): the %s %v it mounts is %v", job.Metadata["name"], ev, o.Kind, o.Metadata["name"], err)
						}
					}
				}
			}
			if jobs < 5 {
				t.Fatalf("%d hook Jobs rendered, want chain-key, relay-session, pre-upgrade, pre-rollback, pre-delete", jobs)
			}
		})
	}
}
