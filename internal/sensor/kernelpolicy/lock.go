// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import "errors"

// The reconciler lock keeps a one-shot --tetragon-cleanup and a helper that
// loads policies (observe, enforce) apart. The helper holds it for as long as
// it reconciles; a cleanup takes it for the length of its run. Without it, a
// cleanup under a running helper removes policies the helper still records
// as applied, and the helper reads their absence as an operator's deletion
// and never loads them again until the intent changes.

// ErrReconcilerRunning says a sensor helper that loads Tetragon policies
// holds the reconciler lock.
var ErrReconcilerRunning = errors.New("a sensor helper is reconciling its Tetragon policies; stop it first (systemctl stop defenseclaw-sensor-helper)")

// LockForCleanup takes the reconciler lock for a one-shot cleanup, without
// waiting. It returns ErrReconcilerRunning while a helper that loads
// policies runs: the policies are that helper's to manage. Any other error
// means the lock could not be taken; cleanup must leave the record intact.
func LockForCleanup(dirs Dirs) (func(), error) { return tryLock(dirs) }
