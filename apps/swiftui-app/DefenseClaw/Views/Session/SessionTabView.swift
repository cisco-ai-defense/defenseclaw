import SwiftUI
import DefenseClawKit

struct SessionTabView: View {
    let session: AgentSession
    @State private var viewModel: SessionViewModel

    init(session: AgentSession) {
        self.session = session
        self._viewModel = State(initialValue: SessionViewModel(session: session))
    }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                ChatView(viewModel: viewModel)
                ChatInputView(viewModel: viewModel)
            }
            .frame(minWidth: 400)

            GovernanceSidebar(viewModel: viewModel)
                .frame(minWidth: 250, idealWidth: 300, maxWidth: 400)
        }
        .navigationTitle("Session")
        .task {
            await viewModel.refreshGovernance()
        }
    }
}
