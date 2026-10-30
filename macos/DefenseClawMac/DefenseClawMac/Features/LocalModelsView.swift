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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

struct LocalModelsView: View {
    let models: [AIModelDiscoveryRow]
    let search: String
    @State private var filter = AIModelDiscoveryFilter()
    @State private var selection: AIModelDiscoveryRowID?

    private var rows: [AIModelDiscoveryRow] {
        let effective = filter.preservingLegacySnapshot(models)
        return models.filter { effective.includes($0) && $0.matches(search) }
    }
    private var selected: AIModelDiscoveryRow? { rows.first { $0.id == selection } }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Toggle("Show all models", isOn: $filter.showAllModels)
                Picker("Modality", selection: $filter.modality) {
                    ForEach(AIModelModalityFilter.allCases) { Text($0.displayName).tag($0) }
                }
                Picker("Relevance", selection: $filter.relevance) {
                    ForEach(AIModelRelevanceFilter.allCases) { Text($0.displayName).tag($0) }
                }
                Text("\(rows.count) of \(models.count)").font(.caption.monospacedDigit())
            }.padding(.horizontal, 12)
            if rows.isEmpty {
                DCEmptyState(title: models.isEmpty ? "No local models" : "No matching models",
                             message: models.isEmpty ? "No identified local models were reported by the gateway." : "Adjust the filters or Show all models to include lower-confidence and embedded artifacts.",
                             systemImage: "cpu")
            } else {
                Table(rows, selection: $selection) {
                    TableColumn("Model") { Text($0.modelID).font(.callout.weight(.medium)) }.width(min: 150, ideal: 220)
                    TableColumn("State") { StatePill(raw: $0.state) }.width(80)
                    TableColumn("Owner") { Text($0.ownerApplications.joined(separator: ", ")) }
                    TableColumn("Modality") { Text($0.effectiveModality.displayName) }
                    TableColumn("Relevance") { Text($0.effectiveRelevance.displayName) }
                    TableColumn("Confidence") { row in
                        Text(row.confidenceDisplayLabel).accessibilityLabel(row.confidenceAccessibilityLabel)
                    }
                    TableColumn("Status / format") { Text(($0.statuses + $0.formats).joined(separator: ", ")) }
                    TableColumn("Sources") { Text($0.detectors.joined(separator: ", ")) }
                }
            }
        }
        .dcInspector(isPresented: Binding(get: { selected != nil }, set: { if !$0 { selection = nil } })) {
            if let row = selected {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(row.modelID).font(.headline)
                        Text("\(row.count) observations · \(row.confidenceAccessibilityLabel)")
                        if let lineage = row.provenance {
                            Text("Publisher: \(lineage.publisher)\nCountry: \(lineage.countryDisplay)\nRoot model: \(lineage.rootModel)\nBase models: \(lineage.baseModels.joined(separator: ", "))\nSource: \(lineage.source)")
                        }
                        ForEach(Array(row.signals.enumerated()), id: \.offset) { _, signal in
                            Divider()
                            Text("\(signal.product) · \(signal.detector)")
                            if let model = signal.model { Text(AIDiscoveryGrouping.modelDetail(model)) }
                            if let runtime = signal.runtime { Text(AIDiscoveryGrouping.runtimeDetail(runtime, sandboxName: signal.sandboxName)) }
                        }
                    }.font(.caption).textSelection(.enabled).padding(16)
                }
            }
        }
    }
}
