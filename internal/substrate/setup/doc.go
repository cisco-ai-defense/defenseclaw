// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Package setup holds the delivery logic of DefenseClaw on Agent Substrate
// that runs outside the gateway's request path: the SubstrateInstall overlay
// `defenseclaw substrate setup` writes (and `--remove` takes back), the
// OpenFGA access policies DefenseClaw needs, the credential provider
// namespace grant, the store-schema rollback check, and the steps of the
// Helm chart's hook Jobs (deploy/helm/defenseclaw-substrate).
//
// Everything here works on plain values and two small interfaces
// (SubstrateAPI, KubeAPI), so the CLI, the hook Jobs and the tests share one
// implementation.
package setup
