import SwiftUI
import DefenseClawKit

struct ChatView: View {
    @Bindable var viewModel: SessionViewModel

    var body: some View {
        ScrollView {
            ScrollViewReader { proxy in
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(viewModel.session.messages) { message in
                        MessageBubble(message: message, viewModel: viewModel)
                            .id(message.id)
                    }
                }
                .padding()
                .onChange(of: viewModel.session.messages.count) { _, _ in
                    if let lastMessage = viewModel.session.messages.last {
                        proxy.scrollTo(lastMessage.id, anchor: .bottom)
                    }
                }
            }
        }
    }
}
