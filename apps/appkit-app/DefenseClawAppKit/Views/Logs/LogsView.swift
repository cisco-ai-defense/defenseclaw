import SwiftUI
import AppKit
import DefenseClawKit

/// Application logs viewer with live tail, filtering, search, and export.
struct LogsView: View {
    @State private var filterLevel: LogLevel = .debug
    @State private var filterCategory: String? = nil
    @State private var searchText = ""
    @State private var autoScroll = true
    @State private var showExportMenu = false

    private let logger = AppLogger.shared

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            toolbar
            Divider()

            // Log entries table
            logTable

            Divider()

            // Status bar
            statusBar
        }
        .frame(minWidth: 700, minHeight: 400)
    }

    // MARK: - Toolbar

    private var toolbar: some View {
        HStack(spacing: 12) {
            Text("LOGS")
                .font(.system(.headline, design: .monospaced))
                .fontWeight(.bold)
                .foregroundStyle(Color(nsColor: .systemBlue))

            Divider().frame(height: 20)

            // Level filter
            Picker("Level", selection: $filterLevel) {
                ForEach(LogLevel.allCases, id: \.self) { level in
                    Text(level.rawValue).tag(level)
                }
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 280)

            // Category filter
            Picker("Category", selection: Binding(
                get: { filterCategory ?? "All" },
                set: { filterCategory = $0 == "All" ? nil : $0 }
            )) {
                Text("All").tag("All")
                ForEach(logger.categories, id: \.self) { cat in
                    Text(cat).tag(cat)
                }
            }
            .frame(maxWidth: 130)

            // Search
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search logs...", text: $searchText)
                    .textFieldStyle(.plain)
                if !searchText.isEmpty {
                    Button {
                        searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Color(nsColor: .textBackgroundColor))
            .cornerRadius(6)
            .frame(maxWidth: 200)

            Spacer()

            // Auto-scroll toggle
            Toggle(isOn: $autoScroll) {
                Image(systemName: "arrow.down.to.line")
            }
            .toggleStyle(.button)
            .help("Auto-scroll to latest")

            // Export button
            Button {
                exportLogs()
            } label: {
                Label("Export", systemImage: "square.and.arrow.up")
                    .font(.caption)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    // MARK: - Log Table

    private var logTable: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    // Column headers
                    logHeader

                    let filtered = logger.filtered(minLevel: filterLevel, category: filterCategory, search: searchText.isEmpty ? nil : searchText)
                    ForEach(filtered) { entry in
                        LogRow(entry: entry)
                            .id(entry.id)
                    }
                }
            }
            .onChange(of: logger.entryCount) { _, _ in
                if autoScroll {
                    let filtered = logger.filtered(minLevel: filterLevel, category: filterCategory, search: searchText.isEmpty ? nil : searchText)
                    if let last = filtered.last {
                        withAnimation {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
        }
    }

    private var logHeader: some View {
        HStack(spacing: 0) {
            Text("TIME")
                .frame(width: 100, alignment: .leading)
            Text("LEVEL")
                .frame(width: 60, alignment: .leading)
            Text("CATEGORY")
                .frame(width: 90, alignment: .leading)
            Text("MESSAGE")
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.system(.caption2, design: .monospaced))
        .fontWeight(.bold)
        .foregroundStyle(Color(nsColor: .systemBlue))
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    // MARK: - Status Bar

    private var statusBar: some View {
        HStack {
            let filtered = logger.filtered(minLevel: filterLevel, category: filterCategory, search: searchText.isEmpty ? nil : searchText)
            Text("\(filtered.count) of \(logger.entryCount) entries")
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)

            Spacer()

            Text("Log file: \(logger.logFilePath)")
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.tertiary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .background(Color(nsColor: .windowBackgroundColor).opacity(0.8))
    }

    // MARK: - Export

    private func exportLogs() {
        let panel = NSSavePanel()
        let timestamp = {
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd_HHmmss"
            return f.string(from: Date())
        }()
        panel.nameFieldStringValue = "defenseclaw-logs-\(timestamp).log"
        panel.allowedContentTypes = [.text, .log]
        panel.canCreateDirectories = true

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            do {
                let content = logger.exportLogContent()
                try content.write(to: url, atomically: true, encoding: .utf8)
                logger.info("app", "Logs exported", details: url.path)
            } catch {
                logger.error("app", "Log export failed", details: "\(error)")
            }
        }
    }
}

// MARK: - Log Row

struct LogRow: View {
    let entry: LogEntry

    var body: some View {
        HStack(spacing: 0) {
            Text(formatTime(entry.timestamp))
                .frame(width: 100, alignment: .leading)

            Text(entry.level.rawValue)
                .fontWeight(.bold)
                .foregroundStyle(levelColor)
                .frame(width: 60, alignment: .leading)

            Text(entry.category)
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .leading)

            VStack(alignment: .leading, spacing: 1) {
                Text(entry.message)
                    .lineLimit(2)
                if let details = entry.details, !details.isEmpty {
                    Text(details)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.system(.caption, design: .monospaced))
        .padding(.horizontal, 12)
        .padding(.vertical, 3)
        .background(rowBackground)
        .contextMenu {
            Button("Copy Line") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(entry.formatted, forType: .string)
            }
        }
    }

    private var levelColor: Color {
        switch entry.level {
        case .debug: return .secondary
        case .info: return .blue
        case .warn: return .orange
        case .error: return .red
        }
    }

    private var rowBackground: Color {
        switch entry.level {
        case .error: return Color.red.opacity(0.06)
        case .warn: return Color.orange.opacity(0.04)
        default: return .clear
        }
    }

    private func formatTime(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f.string(from: date)
    }
}
