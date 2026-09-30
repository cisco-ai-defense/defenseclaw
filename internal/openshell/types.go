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

package openshell

import (
	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// SDK types the Client exposes. They are aliases so values pass straight
// through, but callers name them through this package: an SDK bump then
// changes one file instead of every consumer.
type (
	Sandbox              = v1.Sandbox
	SandboxSpec          = v1.SandboxSpec
	SandboxTemplate      = v1.SandboxTemplate
	SandboxStatus        = v1.SandboxStatus
	SandboxCondition     = v1.SandboxCondition
	SandboxPhase         = v1.SandboxPhase
	EndpointStatus       = v1.EndpointStatus
	ConfigAdmission      = types.SandboxConfigurationAdmission
	ConfigAdmissionState = types.ConfigurationAdmissionState
	DeletionResult       = v1.DeletionResult
	DeletionOutcome      = v1.DeletionOutcome
	GatewayInfo          = v1.GatewayInfo
	ComputeDriverInfo    = v1.ComputeDriverInfo
	Provider             = v1.Provider
	ProviderSpec         = v1.ProviderSpec
	AttachProviderResult = v1.AttachProviderResult
	DetachProviderResult = v1.DetachProviderResult
	ProviderProfile      = v1.ProviderProfile
	ProfileCredential    = v1.ProfileCredential
	ProfileCategory      = v1.ProfileCategory
	NetworkEndpoint      = v1.NetworkEndpoint
	NetworkBinary        = v1.NetworkBinary
	ProfileImportItem    = v1.ProfileImportItem
	ProfileDiagnostic    = v1.ProfileDiagnostic
	ImportResult         = v1.ImportResult
	UpdateResult         = v1.UpdateResult
	LintResult           = v1.LintResult
	DraftPolicy          = v1.DraftPolicy
	PolicyChunk          = v1.PolicyChunk
	DraftChunkApproval   = v1.DraftChunkApproval
	ApproveResult        = v1.ApproveResult
	ApproveAllResult     = v1.ApproveAllResult
	SandboxConfig        = v1.SandboxConfig
	GatewayConfig        = v1.GatewayConfig
	ConfigUpdateResult   = v1.ConfigUpdateResult
	SettingValue         = v1.SettingValue
	EffectiveSetting     = v1.EffectiveSetting
	PolicySource         = v1.PolicySource
	PolicyStatusResult   = v1.PolicyStatusResult
	PolicyRevision       = v1.SandboxPolicyRevision
	PolicyLoadStatus     = v1.PolicyLoadStatus
	PolicyMergeOperation = v1.PolicyMergeOperation
	NetworkPolicyRule    = v1.NetworkPolicyRule
	StatusError          = v1.StatusError
)

// Sandbox phases.
const (
	PhaseProvisioning = v1.SandboxProvisioning
	PhaseReady        = v1.SandboxReady
	PhaseError        = v1.SandboxError
	PhaseDeleting     = v1.SandboxDeleting
	PhaseUnknown      = v1.SandboxUnknown
	PhaseStopping     = v1.SandboxStopping
	PhaseStopped      = v1.SandboxStopped
	PhaseStarting     = v1.SandboxStarting
	PhaseCompleted    = v1.SandboxCompleted
)

// Configuration admission states.
const (
	AdmissionUnknown  = types.ConfigurationAdmissionUnknown
	AdmissionPending  = types.ConfigurationAdmissionPending
	AdmissionAccepted = types.ConfigurationAdmissionAccepted
	AdmissionRejected = types.ConfigurationAdmissionRejected
)

// Setting value kinds.
const (
	SettingString = v1.SettingValueString
	SettingBool   = v1.SettingValueBool
	SettingInt    = v1.SettingValueInt
	SettingBytes  = v1.SettingValueBytes
)

// Typed error predicates. They see through fmt.Errorf wrapping.
var (
	IsNotFound         = v1.IsNotFound
	IsAlreadyExists    = v1.IsAlreadyExists
	IsUnavailable      = v1.IsUnavailable
	IsPermissionDenied = v1.IsPermissionDenied
	IsInvalidArgument  = v1.IsInvalidArgument
	IsDeadlineExceeded = v1.IsDeadlineExceeded
	IsConflict         = v1.IsConflict
	IsUnauthenticated  = v1.IsUnauthenticated
	IsUnimplemented    = v1.IsUnimplemented
)
