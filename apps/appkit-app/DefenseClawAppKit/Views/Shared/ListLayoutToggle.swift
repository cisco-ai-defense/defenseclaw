import SwiftUI

/// Layout preference for dense lists that can render either as tiles or as a
/// compact table. Reusable across busy views (scan targets, catalogs, etc.).
enum ListLayoutMode: String, CaseIterable, Hashable {
    case tile
    case table

    var systemImage: String {
        switch self {
        case .tile: return "square.grid.2x2"
        case .table: return "list.bullet"
        }
    }

    var label: String {
        switch self {
        case .tile: return "Tiles"
        case .table: return "Table"
        }
    }
}

/// Compact segmented control that switches a busy list between tile and table
/// layout. Pair with a `@State ListLayoutMode` on the hosting view.
struct ListLayoutToggle: View {
    @Binding var mode: ListLayoutMode

    var body: some View {
        Picker("Layout", selection: $mode) {
            ForEach(ListLayoutMode.allCases, id: \.self) { mode in
                Image(systemName: mode.systemImage)
                    .help(mode.label)
                    .tag(mode)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .fixedSize()
        .help("Switch between tile and table layout")
    }
}
