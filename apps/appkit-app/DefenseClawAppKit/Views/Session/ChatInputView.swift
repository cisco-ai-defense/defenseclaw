import SwiftUI
import DefenseClawKit

struct ChatInputView: View {
    @Bindable var viewModel: SessionViewModel

    private var isStreaming: Bool {
        viewModel.session.messages.last?.isStreaming == true
    }

    private var canSend: Bool {
        !viewModel.inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            Divider()

            HStack(alignment: .bottom, spacing: 8) {
                ChatTextView(
                    text: $viewModel.inputText,
                    placeholder: "Send a message... (Enter to send, Shift+Enter for new line)",
                    onSubmit: {
                        if canSend {
                            viewModel.sendMessage()
                        }
                    }
                )
                .frame(minHeight: 36, maxHeight: 120)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                )

                if isStreaming {
                    Button {
                        viewModel.stopStreaming()
                    } label: {
                        Image(systemName: "stop.circle.fill")
                            .font(.system(size: 24))
                            .foregroundStyle(.red)
                    }
                    .buttonStyle(.borderless)
                    .help("Stop response")
                } else {
                    Button {
                        viewModel.sendMessage()
                    } label: {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.system(size: 24))
                            .foregroundStyle(canSend ? Color.accentColor : Color.gray.opacity(0.4))
                    }
                    .buttonStyle(.borderless)
                    .disabled(!canSend)
                    .help("Send message")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(Color(nsColor: .windowBackgroundColor))
        }
    }
}
