import SwiftUI
import DefenseClawKit

struct SessionContentView: View {
    @Bindable var viewModel: SessionViewModel

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                ChatView(viewModel: viewModel)
                ChatInputView(viewModel: viewModel)
            }

            Divider()

            GovernanceSidebarView(viewModel: viewModel)
                .frame(width: 300)
        }
        .task {
            await viewModel.refreshGovernance()
        }
    }
}
