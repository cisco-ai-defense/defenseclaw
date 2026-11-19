// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fleet

// CheckWorkerDrain is the check id of a worker pool roll in progress.
const CheckWorkerDrain = "worker_drain"

// WorkerDrain is what verify read of the cluster's workers: how many are
// DRAINING (a worker pool roll or a node drain) and how many actors still run
// on them. Note says why it could not be read ("" when it was).
type WorkerDrain struct {
	Draining, RunningOn int
	Note                string
}

// CheckWorkerDrainRunning: an actor still RUNNING on a draining worker when
// the worker's pod stops is CRASHED by Substrate and loses its unsaved work
// (substrate-1:GAP-0449). The DefenseClaw controller suspends the actors it
// manages off a draining worker and resumes them on another one; verify warns
// while any actor still runs there, so the administrator can wait, or suspend
// the others first.
func CheckWorkerDrainRunning(o Observed) Check {
	w := o.WorkerDrain
	switch {
	case w == nil:
		return result(CheckWorkerDrain, Skip, "", "the workers were not read")
	case w.Note != "":
		return result(CheckWorkerDrain, Skip, "", "could not read the workers: %s", w.Note)
	case w.Draining == 0:
		return result(CheckWorkerDrain, Pass, "", "no worker is draining")
	case w.RunningOn == 0:
		return result(CheckWorkerDrain, Pass, "", "%d draining worker(s) (a worker pool roll), and no actor runs on them", w.Draining)
	}
	return result(CheckWorkerDrain, Warn, "", "a worker pool roll is in progress: %d draining worker(s) still run %d actor(s), "+
		"and an actor still running there when its worker stops crashes and loses its work. The DefenseClaw controller suspends the "+
		"actors it manages and resumes them on another worker within a pass or two; suspend any other actor yourself "+
		"(kubectl ate suspend actor NAME -a ATESPACE) before the old workers stop, and run verify again", w.Draining, w.RunningOn)
}
