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

// Cisco design system (spec §6): brand palette + severity/state mappings.
// Colors defined in code (light/dark aware) so no asset catalog is required.

import SwiftUI

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }

    /// Light/dark adaptive color.
    static func adaptive(light: UInt32, dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return NSColor(Color(hex: isDark ? dark : light))
        })
    }
}

enum Cisco {
    // Brand
    static let blue = Color.adaptive(light: 0x049FD9, dark: 0x04AEED)
    static let midnight = Color(hex: 0x0D274D)
    static let sky = Color(nsColor: .systemCyan)

    // System status colors preserve the Cisco semantics while adapting to
    // appearance and Increase Contrast preferences.
    static let green = Color(nsColor: .systemGreen)
    static let red = Color(nsColor: .systemRed)
    static let orange = Color(nsColor: .systemOrange)
    static let yellow = Color(nsColor: .systemYellow)
    static let magenta = Color(nsColor: .systemPurple)

    // Surfaces
    static let surfacePanel = Color.adaptive(light: 0xF5F7FA, dark: 0x111B2C)
    static let surfaceRaised = Color.adaptive(light: 0xFFFFFF, dark: 0x16233A)

    static func severityColor(_ s: Severity) -> Color {
        switch s {
        case .critical: red
        case .high: orange
        case .medium: yellow
        case .low: sky
        case .info: Color.secondary
        }
    }

    static func stateColor(_ s: EntityState) -> Color {
        switch s {
        case .active: green
        case .blocked: red
        case .warn: orange
        case .quarantined: magenta
        case .disabled: Color.secondary.opacity(0.6)
        }
    }

    static func stateColor(raw: String) -> Color {
        stateColor(EntityState.classify(raw))
    }
}
