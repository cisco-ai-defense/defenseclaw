import SwiftUI
import DefenseClawKit

struct ChatInputView: View {
    @Bindable var viewModel: SessionViewModel

    var body: some View {
        VStack(spacing: 8) {
            Divider()

            HStack(alignment: .bottom, spacing: 8) {
                TextEditor(text: $viewModel.inputText)
                    .frame(minHeight: 40, maxHeight: 120)
                    .padding(4)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                    )

                if viewModel.session.messages.last?.isStreaming == true {
                    Button {
                        viewModel.stopStreaming()
                    } label: {
                        Image(systemName: "stop.circle.fill")
                            .font(.title2)
                    }
                    .buttonStyle(.borderless)
                } else {
                    Button {
                        viewModel.sendMessage()
                    } label: {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.title2)
                    }
                    .buttonStyle(.borderless)
                    .disabled(viewModel.inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .padding(.horizontal)
            .padding(.bottom, 8)
        }
    }
}
