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

// Shared UI components (spec §6.2): badges, pills, cards, chips, diff view.
// Color is never the only signal — every colored element carries a label.

import SwiftUI

struct SeverityBadge: View {
    let severity: Severity

    private var foreground: Color {
        switch severity {
        case .critical: .white
        case .high, .medium, .low: .black
        case .info: .primary
        }
    }

    private var background: Color {
        severity == .info
            ? Cisco.severityColor(severity).opacity(0.18)
            : Cisco.severityColor(severity).opacity(0.88)
    }

    var body: some View {
        Text(severity.rawValue)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(background)
            .foregroundStyle(foreground)
            .clipShape(Capsule())
    }
}

struct StatePill: View {
    let raw: String
    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(Cisco.stateColor(raw: raw)).frame(width: 7, height: 7)
            Text(raw.lowercased())
                .font(.caption.weight(.medium))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Cisco.stateColor(raw: raw).opacity(0.12))
        .clipShape(Capsule())
    }
}

struct StaleBadge: View {
    let date: Date
    var body: some View {
        if date.isStale {
            Label("stale · \(DCDates.relative(date))", systemImage: "clock.badge.exclamationmark")
                .font(.caption2)
                .foregroundStyle(Cisco.orange)
        }
    }
}

struct StatCard<Content: View>: View {
    let title: String
    let value: String
    var tint: Color = Cisco.blue
    @ViewBuilder var detail: Content

    init(title: String, value: String, tint: Color = Cisco.blue, @ViewBuilder detail: () -> Content = { EmptyView() }) {
        self.title = title
        self.value = value
        self.tint = tint
        self.detail = detail()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 26, weight: .bold, design: .rounded))
                .foregroundStyle(tint)
            detail
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Cisco.surfaceRaised, in: RoundedRectangle(cornerRadius: 10))
    }
}

struct DCCard<Content: View>: View {
    let title: String
    var systemImage: String?
    /// When true the card stretches to fill the available height so siblings
    /// in an equal-height row share one rectangle height (content stays top).
    var fillHeight: Bool = false
    @ViewBuilder var content: Content

    init(_ title: String, systemImage: String? = nil, fillHeight: Bool = false, @ViewBuilder content: () -> Content) {
        self.title = title
        self.systemImage = systemImage
        self.fillHeight = fillHeight
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                if let systemImage {
                    Image(systemName: systemImage).foregroundStyle(Cisco.blue)
                }
                Text(title).font(.headline)
                Spacer()
            }
            content
            if fillHeight { Spacer(minLength: 0) }
        }
        .padding(14)
        .frame(maxWidth: .infinity, maxHeight: fillHeight ? .infinity : nil, alignment: .topLeading)
        .background(Cisco.surfacePanel, in: RoundedRectangle(cornerRadius: 12))
    }
}

/// Shared connector filter. A menu remains compact as connector counts grow
/// and exposes one native selected value to keyboard and assistive technology.
struct ConnectorFilterChip: View {
    let names: [String]
    @Binding var selection: String   // "" = All

    var body: some View {
        if names.count > 1 {
            Picker("Connector", selection: $selection) {
                Text("All Connectors").tag("")
                ForEach(names, id: \.self) { name in
                    Text(name).tag(name)
                }
            }
            .pickerStyle(.menu)
            .fixedSize()
        }
    }
}

/// A native single-select control: segmented for short sets, menu for long sets.
struct FilterChipRow<T: Hashable>: View {
    let label: String
    let options: [(label: String, value: T)]
    @Binding var selection: T

    init(_ label: String, options: [(label: String, value: T)], selection: Binding<T>) {
        self.label = label
        self.options = options
        self._selection = selection
    }

    @ViewBuilder
    var body: some View {
        if options.count <= 6 {
            picker.pickerStyle(.segmented)
        } else {
            picker
                .pickerStyle(.menu)
                .fixedSize()
        }
    }

    private var picker: some View {
        Picker(label, selection: $selection) {
            ForEach(options, id: \.value) { option in
                Text(option.label).tag(option.value)
            }
        }
    }
}

/// Gives dashboard navigation cards a visible boundary and hover/press state.
struct InteractiveCardButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> Body {
        Body(configuration: configuration)
    }

    struct Body: View {
        let configuration: Configuration
        @State private var hovering = false

        var body: some View {
            configuration.label
                .contentShape(RoundedRectangle(cornerRadius: 10))
                .overlay {
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(
                            Cisco.blue.opacity(hovering || configuration.isPressed ? 0.75 : 0.22),
                            lineWidth: hovering || configuration.isPressed ? 1.5 : 1
                        )
                }
                .opacity(configuration.isPressed ? 0.82 : 1)
                .onHover { hovering = $0 }
        }
    }
}

/// Red/green before-after JSON diff (Activity detail, Setup review).
struct DiffView: View {
    let before: String
    let after: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            diffColumn("Before", text: before, tint: Cisco.red, prefix: "−")
            diffColumn("After", text: after, tint: Cisco.green, prefix: "+")
        }
    }

    private func diffColumn(_ title: String, text: String, tint: Color, prefix: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.weight(.semibold)).foregroundStyle(tint)
            ScrollView {
                Text(text.isEmpty ? "(empty)" : text)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .background(tint.opacity(0.07), in: RoundedRectangle(cornerRadius: 6))
        }
        .frame(maxWidth: .infinity)
    }
}

struct KeyValueGrid: View {
    let pairs: [(String, String)]
    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 5) {
            ForEach(Array(pairs.enumerated()), id: \.offset) { _, pair in
                GridRow {
                    Text(pair.0)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: true, vertical: false)
                    Text(pair.1)
                        .font(.caption)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct DCEmptyState: View {
    let title: String
    let message: String
    var systemImage: String = "tray"

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: systemImage)
        } description: {
            Text(message)
        }
    }
}

struct ConfidenceGauge: View {
    let value: Double // 0...1

    private var normalizedValue: Double { AIConfidence.clampedUnit(value) }

    var body: some View {
        HStack(spacing: 6) {
            ProgressView(value: normalizedValue)
                .progressViewStyle(.linear)
                .tint(normalizedValue > 0.8 ? Cisco.green : normalizedValue > 0.5 ? Cisco.orange : Cisco.red)
                .frame(width: 70)
            Text("\(AIConfidence.percent(normalizedValue))%")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }
}

extension View {
    func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
