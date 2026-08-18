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

package semantic

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

func projectParseStatus(value actionfacts.ParseStatus) (semanticpb.ParseStatus, bool) {
	switch value {
	case actionfacts.StatusNotApplicable:
		return semanticpb.ParseStatus_PARSE_STATUS_NOT_APPLICABLE, true
	case actionfacts.StatusComplete:
		return semanticpb.ParseStatus_PARSE_STATUS_COMPLETE, true
	case actionfacts.StatusPartial:
		return semanticpb.ParseStatus_PARSE_STATUS_PARTIAL, true
	case actionfacts.StatusUnsupported:
		return semanticpb.ParseStatus_PARSE_STATUS_UNSUPPORTED, true
	case actionfacts.StatusInvalid:
		return semanticpb.ParseStatus_PARSE_STATUS_INVALID, true
	case actionfacts.StatusLimitExceeded:
		return semanticpb.ParseStatus_PARSE_STATUS_LIMIT_EXCEEDED, true
	case actionfacts.StatusAmbiguous:
		return semanticpb.ParseStatus_PARSE_STATUS_AMBIGUOUS, true
	default:
		return semanticpb.ParseStatus_PARSE_STATUS_UNSPECIFIED, false
	}
}

func projectDialect(value actionfacts.Dialect) (semanticpb.Dialect, bool) {
	switch value {
	case actionfacts.DialectNone:
		return semanticpb.Dialect_DIALECT_NONE, true
	case actionfacts.DialectArgv:
		return semanticpb.Dialect_DIALECT_ARGV, true
	case actionfacts.DialectPOSIX:
		return semanticpb.Dialect_DIALECT_POSIX, true
	case actionfacts.DialectPowerShell:
		return semanticpb.Dialect_DIALECT_POWERSHELL, true
	case actionfacts.DialectCMD:
		return semanticpb.Dialect_DIALECT_CMD, true
	case actionfacts.DialectMixed:
		return semanticpb.Dialect_DIALECT_MIXED, true
	default:
		return semanticpb.Dialect_DIALECT_UNSPECIFIED, false
	}
}

func projectIssue(value actionfacts.IssueCode) (semanticpb.IssueCode, bool) {
	switch value {
	case actionfacts.IssueInvalidJSON:
		return semanticpb.IssueCode_ISSUE_CODE_INVALID_JSON, true
	case actionfacts.IssueInvalidUTF8:
		return semanticpb.IssueCode_ISSUE_CODE_INVALID_UTF8, true
	case actionfacts.IssueInvalidSyntax:
		return semanticpb.IssueCode_ISSUE_CODE_INVALID_SYNTAX, true
	case actionfacts.IssueDynamicWord:
		return semanticpb.IssueCode_ISSUE_CODE_DYNAMIC_WORD, true
	case actionfacts.IssueUnsupportedConstruct:
		return semanticpb.IssueCode_ISSUE_CODE_UNSUPPORTED_CONSTRUCT, true
	case actionfacts.IssueUnknownOperandGrammar:
		return semanticpb.IssueCode_ISSUE_CODE_UNKNOWN_OPERAND_GRAMMAR, true
	case actionfacts.IssueConflictingSources:
		return semanticpb.IssueCode_ISSUE_CODE_CONFLICTING_SOURCES, true
	case actionfacts.IssueInputLimit:
		return semanticpb.IssueCode_ISSUE_CODE_INPUT_LIMIT, true
	case actionfacts.IssueNodeLimit:
		return semanticpb.IssueCode_ISSUE_CODE_NODE_LIMIT, true
	case actionfacts.IssueDepthLimit:
		return semanticpb.IssueCode_ISSUE_CODE_DEPTH_LIMIT, true
	case actionfacts.IssueFactLimit:
		return semanticpb.IssueCode_ISSUE_CODE_FACT_LIMIT, true
	case actionfacts.IssueWrapperLimit:
		return semanticpb.IssueCode_ISSUE_CODE_WRAPPER_LIMIT, true
	case actionfacts.IssueDuplicateJSONKey:
		return semanticpb.IssueCode_ISSUE_CODE_DUPLICATE_JSON_KEY, true
	case actionfacts.IssueInternalParserFailure:
		return semanticpb.IssueCode_ISSUE_CODE_INTERNAL_PARSER_FAILURE, true
	default:
		return semanticpb.IssueCode_ISSUE_CODE_UNSPECIFIED, false
	}
}

func projectCommandKind(value actionfacts.CommandKind) (semanticpb.CommandKind, bool) {
	switch value {
	case actionfacts.CommandKindProcess:
		return semanticpb.CommandKind_COMMAND_KIND_PROCESS, true
	case actionfacts.CommandKindShellRedirect:
		return semanticpb.CommandKind_COMMAND_KIND_SHELL_REDIRECT, true
	default:
		return semanticpb.CommandKind_COMMAND_KIND_UNSPECIFIED, false
	}
}

func projectCommandEffect(value actionfacts.CommandEffect) (semanticpb.CommandEffect, bool) {
	switch value {
	case actionfacts.EffectExecute:
		return semanticpb.CommandEffect_COMMAND_EFFECT_EXECUTE, true
	case actionfacts.EffectPreview:
		return semanticpb.CommandEffect_COMMAND_EFFECT_PREVIEW, true
	case actionfacts.EffectUncertain:
		return semanticpb.CommandEffect_COMMAND_EFFECT_UNCERTAIN, true
	default:
		return semanticpb.CommandEffect_COMMAND_EFFECT_UNSPECIFIED, false
	}
}

func projectQuote(value actionfacts.QuoteKind) (semanticpb.QuoteKind, bool) {
	switch value {
	case actionfacts.QuoteNone:
		return semanticpb.QuoteKind_QUOTE_KIND_NONE, true
	case actionfacts.QuoteSingle:
		return semanticpb.QuoteKind_QUOTE_KIND_SINGLE, true
	case actionfacts.QuoteDouble:
		return semanticpb.QuoteKind_QUOTE_KIND_DOUBLE, true
	case actionfacts.QuoteMixed:
		return semanticpb.QuoteKind_QUOTE_KIND_MIXED, true
	default:
		return semanticpb.QuoteKind_QUOTE_KIND_UNSPECIFIED, false
	}
}

func projectOperation(value actionfacts.OperationKind) (semanticpb.OperationKind, bool) {
	switch value {
	case actionfacts.OperationExecute:
		return semanticpb.OperationKind_OPERATION_KIND_EXECUTE, true
	case actionfacts.OperationRead:
		return semanticpb.OperationKind_OPERATION_KIND_READ, true
	case actionfacts.OperationWrite:
		return semanticpb.OperationKind_OPERATION_KIND_WRITE, true
	case actionfacts.OperationAppend:
		return semanticpb.OperationKind_OPERATION_KIND_APPEND, true
	case actionfacts.OperationDelete:
		return semanticpb.OperationKind_OPERATION_KIND_DELETE, true
	case actionfacts.OperationCopy:
		return semanticpb.OperationKind_OPERATION_KIND_COPY, true
	case actionfacts.OperationMove:
		return semanticpb.OperationKind_OPERATION_KIND_MOVE, true
	case actionfacts.OperationList:
		return semanticpb.OperationKind_OPERATION_KIND_LIST, true
	case actionfacts.OperationSearch:
		return semanticpb.OperationKind_OPERATION_KIND_SEARCH, true
	case actionfacts.OperationFetch:
		return semanticpb.OperationKind_OPERATION_KIND_FETCH, true
	case actionfacts.OperationUpload:
		return semanticpb.OperationKind_OPERATION_KIND_UPLOAD, true
	case actionfacts.OperationConnect:
		return semanticpb.OperationKind_OPERATION_KIND_CONNECT, true
	case actionfacts.OperationListen:
		return semanticpb.OperationKind_OPERATION_KIND_LISTEN, true
	case actionfacts.OperationTunnel:
		return semanticpb.OperationKind_OPERATION_KIND_TUNNEL, true
	case actionfacts.OperationNetworkScan:
		return semanticpb.OperationKind_OPERATION_KIND_NETWORK_SCAN, true
	case actionfacts.OperationDecode:
		return semanticpb.OperationKind_OPERATION_KIND_DECODE, true
	case actionfacts.OperationProcessKill:
		return semanticpb.OperationKind_OPERATION_KIND_PROCESS_KILL, true
	case actionfacts.OperationDiskWrite:
		return semanticpb.OperationKind_OPERATION_KIND_DISK_WRITE, true
	case actionfacts.OperationPrivilege:
		return semanticpb.OperationKind_OPERATION_KIND_PRIVILEGE, true
	case actionfacts.OperationPermissionChange:
		return semanticpb.OperationKind_OPERATION_KIND_PERMISSION_CHANGE, true
	case actionfacts.OperationConfigChange:
		return semanticpb.OperationKind_OPERATION_KIND_CONFIG_CHANGE, true
	case actionfacts.OperationAccountChange:
		return semanticpb.OperationKind_OPERATION_KIND_ACCOUNT_CHANGE, true
	case actionfacts.OperationSchedule:
		return semanticpb.OperationKind_OPERATION_KIND_SCHEDULE, true
	case actionfacts.OperationContainerRun:
		return semanticpb.OperationKind_OPERATION_KIND_CONTAINER_RUN, true
	case actionfacts.OperationWorkloadExec:
		return semanticpb.OperationKind_OPERATION_KIND_WORKLOAD_EXEC, true
	case actionfacts.OperationNamespaceEnter:
		return semanticpb.OperationKind_OPERATION_KIND_NAMESPACE_ENTER, true
	case actionfacts.OperationRootChange:
		return semanticpb.OperationKind_OPERATION_KIND_ROOT_CHANGE, true
	case actionfacts.OperationEnvironmentRead:
		return semanticpb.OperationKind_OPERATION_KIND_ENVIRONMENT_READ, true
	case actionfacts.OperationCredentialRead:
		return semanticpb.OperationKind_OPERATION_KIND_CREDENTIAL_READ, true
	case actionfacts.OperationPolicyBypass:
		return semanticpb.OperationKind_OPERATION_KIND_POLICY_BYPASS, true
	default:
		return semanticpb.OperationKind_OPERATION_KIND_UNSPECIFIED, false
	}
}

func projectPathAccess(value actionfacts.PathAccess) (semanticpb.PathAccess, bool) {
	switch value {
	case actionfacts.PathAccessRead:
		return semanticpb.PathAccess_PATH_ACCESS_READ, true
	case actionfacts.PathAccessWrite:
		return semanticpb.PathAccess_PATH_ACCESS_WRITE, true
	case actionfacts.PathAccessAppend:
		return semanticpb.PathAccess_PATH_ACCESS_APPEND, true
	case actionfacts.PathAccessDelete:
		return semanticpb.PathAccess_PATH_ACCESS_DELETE, true
	case actionfacts.PathAccessExecute:
		return semanticpb.PathAccess_PATH_ACCESS_EXECUTE, true
	case actionfacts.PathAccessList:
		return semanticpb.PathAccess_PATH_ACCESS_LIST, true
	case actionfacts.PathAccessMetadata:
		return semanticpb.PathAccess_PATH_ACCESS_METADATA, true
	case actionfacts.PathAccessConnect:
		return semanticpb.PathAccess_PATH_ACCESS_CONNECT, true
	default:
		return semanticpb.PathAccess_PATH_ACCESS_UNSPECIFIED, false
	}
}

func projectPathFlavor(value actionfacts.PathFlavor) (semanticpb.PathFlavor, bool) {
	switch value {
	case actionfacts.PathFlavorUnknown:
		return semanticpb.PathFlavor_PATH_FLAVOR_UNKNOWN, true
	case actionfacts.PathFlavorPOSIX:
		return semanticpb.PathFlavor_PATH_FLAVOR_POSIX, true
	case actionfacts.PathFlavorWindows:
		return semanticpb.PathFlavor_PATH_FLAVOR_WINDOWS, true
	case actionfacts.PathFlavorDevice:
		return semanticpb.PathFlavor_PATH_FLAVOR_DEVICE, true
	case actionfacts.PathFlavorRegistry:
		return semanticpb.PathFlavor_PATH_FLAVOR_REGISTRY, true
	default:
		return semanticpb.PathFlavor_PATH_FLAVOR_UNSPECIFIED, false
	}
}

func projectNetworkScope(value actionfacts.NetworkScope) (semanticpb.NetworkScope, bool) {
	switch value {
	case actionfacts.NetworkScopeUnknown:
		return semanticpb.NetworkScope_NETWORK_SCOPE_UNKNOWN, true
	case actionfacts.NetworkScopeLoopback:
		return semanticpb.NetworkScope_NETWORK_SCOPE_LOOPBACK, true
	case actionfacts.NetworkScopeLinkLocal:
		return semanticpb.NetworkScope_NETWORK_SCOPE_LINK_LOCAL, true
	case actionfacts.NetworkScopePrivate:
		return semanticpb.NetworkScope_NETWORK_SCOPE_PRIVATE, true
	case actionfacts.NetworkScopePublic:
		return semanticpb.NetworkScope_NETWORK_SCOPE_PUBLIC, true
	default:
		return semanticpb.NetworkScope_NETWORK_SCOPE_UNSPECIFIED, false
	}
}

func projectNetworkTarget(
	value actionfacts.NetworkTargetKind,
) (semanticpb.NetworkTargetKind, bool) {
	switch value {
	case actionfacts.NetworkTargetUnknown:
		return semanticpb.NetworkTargetKind_NETWORK_TARGET_KIND_UNKNOWN, true
	case actionfacts.NetworkTargetSingleHost:
		return semanticpb.NetworkTargetKind_NETWORK_TARGET_KIND_SINGLE_HOST, true
	case actionfacts.NetworkTargetSingleAddressCIDR:
		return semanticpb.NetworkTargetKind_NETWORK_TARGET_KIND_SINGLE_ADDRESS_CIDR, true
	case actionfacts.NetworkTargetMultiAddressCIDR:
		return semanticpb.NetworkTargetKind_NETWORK_TARGET_KIND_MULTI_ADDRESS_CIDR, true
	case actionfacts.NetworkTargetRange:
		return semanticpb.NetworkTargetKind_NETWORK_TARGET_KIND_RANGE, true
	case actionfacts.NetworkTargetList:
		return semanticpb.NetworkTargetKind_NETWORK_TARGET_KIND_LIST, true
	case actionfacts.NetworkTargetGenerated:
		return semanticpb.NetworkTargetKind_NETWORK_TARGET_KIND_GENERATED, true
	default:
		return semanticpb.NetworkTargetKind_NETWORK_TARGET_KIND_UNSPECIFIED, false
	}
}

func projectNetworkAction(value actionfacts.NetworkAction) (semanticpb.NetworkAction, bool) {
	switch value {
	case actionfacts.NetworkConnect:
		return semanticpb.NetworkAction_NETWORK_ACTION_CONNECT, true
	case actionfacts.NetworkListen:
		return semanticpb.NetworkAction_NETWORK_ACTION_LISTEN, true
	case actionfacts.NetworkDownload:
		return semanticpb.NetworkAction_NETWORK_ACTION_DOWNLOAD, true
	case actionfacts.NetworkUpload:
		return semanticpb.NetworkAction_NETWORK_ACTION_UPLOAD, true
	case actionfacts.NetworkDNS:
		return semanticpb.NetworkAction_NETWORK_ACTION_DNS, true
	case actionfacts.NetworkTunnel:
		return semanticpb.NetworkAction_NETWORK_ACTION_TUNNEL, true
	case actionfacts.NetworkScan:
		return semanticpb.NetworkAction_NETWORK_ACTION_SCAN, true
	default:
		return semanticpb.NetworkAction_NETWORK_ACTION_UNSPECIFIED, false
	}
}

func projectDataKind(value actionfacts.DataKind) (semanticpb.DataKind, bool) {
	switch value {
	case actionfacts.DataStdin:
		return semanticpb.DataKind_DATA_KIND_STDIN, true
	case actionfacts.DataStdout:
		return semanticpb.DataKind_DATA_KIND_STDOUT, true
	case actionfacts.DataFile:
		return semanticpb.DataKind_DATA_KIND_FILE, true
	case actionfacts.DataNetwork:
		return semanticpb.DataKind_DATA_KIND_NETWORK, true
	case actionfacts.DataProcess:
		return semanticpb.DataKind_DATA_KIND_PROCESS, true
	default:
		return semanticpb.DataKind_DATA_KIND_UNSPECIFIED, false
	}
}
