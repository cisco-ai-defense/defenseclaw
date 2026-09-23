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

import Foundation

enum AIDiscoveryPrimaryAction: Equatable, Sendable {
    case enable
    case scan

    static func resolve(enabled: Bool) -> Self {
        enabled ? .scan : .enable
    }

    var title: String {
        switch self {
        case .enable: "Enable AI Discovery"
        case .scan: "Scan AI Discovery"
        }
    }

    var label: String {
        switch self {
        case .enable: "Enable AI Discovery"
        case .scan: "Scan Now"
        }
    }

    var systemImage: String {
        switch self {
        case .enable: "power"
        case .scan: "wand.and.rays"
        }
    }

    var arguments: [String] {
        switch self {
        case .enable: ["agent", "discovery", "enable", "--yes"]
        case .scan: ["agent", "discovery", "scan"]
        }
    }

    var category: String {
        switch self {
        case .enable: "setup"
        case .scan: "scan"
        }
    }

    var successEffects: [String] {
        switch self {
        case .enable: ["AI Discovery enabled", "Initial AI usage scan completed"]
        case .scan: ["AI Discovery snapshot refreshed"]
        }
    }
}

enum AIDiscoveryScanRequestStep: Equatable, Sendable {
    case loadStatus
    case showDisabled
    case scan

    static func resolve(statusLoaded: Bool, enabled: Bool) -> Self {
        guard statusLoaded else { return .loadStatus }
        return enabled ? .scan : .showDisabled
    }
}
