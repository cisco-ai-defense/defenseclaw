import SwiftUI
import DefenseClawKit

struct MainWindow: View {
    @Environment(AppViewModel.self) private var appViewModel

    var body: some View {
        @Bindable var appVM = appViewModel

        NavigationSplitView {
            SidebarView()
        } detail: {
            if let session = appViewModel.activeSession {
                SessionTabView(session: session)
            } else {
                ContentUnavailableView(
                    "No Session Selected",
                    systemImage: "shield.slash",
                    description: Text("Select a session from the sidebar or create a new one")
                )
            }
        }
        .navigationTitle("DefenseClaw")
        .sheet(isPresented: $appVM.showNewSessionSheet) {
            NewSessionSheet()
        }
    }
}

struct SidebarView: View {
    @Environment(AppViewModel.self) private var appViewModel

    var body: some View {
        List(selection: Bindable(appViewModel).activeSessionIndex) {
            Section("Sessions") {
                ForEach(Array(appViewModel.sessions.enumerated()), id: \.offset) { index, session in
                    NavigationLink(value: index) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Session \(index + 1)")
                                .font(.headline)
                            Text(session.isConnected ? "Connected" : "Disconnected")
                                .font(.caption)
                                .foregroundStyle(session.isConnected ? .green : .secondary)
                        }
                    }
                }
            }

            Section("Tools") {
                NavigationLink(destination: ScanView()) {
                    Label("Scan", systemImage: "magnifyingglass")
                }
                NavigationLink(destination: PolicyView()) {
                    Label("Policies", systemImage: "doc.text")
                }
            }
        }
        .navigationTitle("DefenseClaw")
        .toolbar {
            Button {
                appViewModel.showNewSessionSheet = true
            } label: {
                Label("New Session", systemImage: "plus")
            }
        }
    }
}
