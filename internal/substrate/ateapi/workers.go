// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ateapi

import "context"

// Draining is the cluster's DRAINING workers, by Worker name and by the
// namespace/pod of their worker pod: an actor's WorkerAssignment names its
// worker both ways (substrate-1:GAP-0449). The controller moves the actors
// off them, and verify reports a pool roll in progress.
type Draining struct {
	Names, Pods map[string]bool
}

// Empty says no worker is draining.
func (d Draining) Empty() bool { return len(d.Names) == 0 && len(d.Pods) == 0 }

// Hosts says whether the actor's current worker is draining, and names its
// worker pod (namespace/pod).
func (d Draining) Hosts(a *Actor) (string, bool) {
	w := a.GetStatus().GetWorkerAssignment()
	if w == nil {
		return "", false
	}
	pod := w.GetWorkerNamespace() + "/" + w.GetWorkerPod()
	if n := w.GetWorker().GetName(); n != "" && d.Names[n] {
		return pod, true
	}
	return pod, w.GetWorkerPod() != "" && d.Pods[pod]
}

// DrainingWorkers lists every worker and keeps the DRAINING ones.
func DrainingWorkers(ctx context.Context, wl WorkerLister) (Draining, error) {
	d := Draining{Names: map[string]bool{}, Pods: map[string]bool{}}
	err := ListAll(ctx, MaxPageSize, wl.ListWorkers, func(w *Worker) error {
		if w.GetStatus().GetState() != WorkerStateDraining {
			return nil
		}
		if n := w.GetMetadata().GetName(); n != "" {
			d.Names[n] = true
		}
		if w.GetWorkerPod() != "" {
			d.Pods[w.GetWorkerNamespace()+"/"+w.GetWorkerPod()] = true
		}
		return nil
	})
	if err != nil {
		return Draining{}, err
	}
	return d, nil
}
