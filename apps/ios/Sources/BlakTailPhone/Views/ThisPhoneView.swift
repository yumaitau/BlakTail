import BlakTailCore
import SwiftUI

struct ThisPhoneView: View {
    @Bindable var model: PhoneModel
    @State private var showingLeave = false
    @AccessibilityFocusState private var focusOnLeave: Bool

    var body: some View {
        Form {
            Section {
                HStack(alignment: .top) {
                    Image(systemName: model.connectionSymbol)
                        .font(.system(size: 30))
                        .foregroundStyle(connectionColour)
                        .accessibilityHidden(true)
                        .frame(minWidth: 44, minHeight: 44)
                    VStack(alignment: .leading) {
                        Text(model.connectionState.label)
                            .font(.title2.weight(.semibold))
                        Text(connectionDescription)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.isBusy {
                        ProgressView()
                            .controlSize(.regular)
                            .accessibilityLabel("Connection change in progress")
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("This iPhone is \(model.connectionState.label.lowercased())")

                if model.connectionState == .connected, let transport = model.observedTransport {
                    VStack(alignment: .leading, spacing: 4) {
                        LabeledContent("Path", value: transport.label)
                        Text(transport.detail)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
            }

            if let session = model.session {
                Section("Network for this iPhone") {
                    Picker("Network", selection: organisationBinding) {
                        ForEach(session.organisations) { organisation in
                            Text(organisation.name).tag(organisation.id)
                        }
                    }
                    .disabled(model.enrollment != nil || model.isBusy)
                    .accessibilityHint("An enrolled iPhone keeps its network until it leaves")

                    if let organisation = model.selectedOrganisation, !organisation.canMutate, model.enrollment == nil {
                        Label(
                            "An owner or admin must enrol this iPhone in this network.",
                            systemImage: "person.badge.shield.checkmark"
                        )
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    }
                }
            } else {
                Section("Account") {
                    Text("Sign in once to choose from every network your account can access.")
                        .foregroundStyle(.secondary)
                    Button("Sign in") {
                        Task { await model.signIn() }
                    }
                    .disabled(model.isBusy || model.consoleBaseURL == nil)
                    .frame(minWidth: 44, minHeight: 44)
                }
            }

            Section {
                Button(model.connectionState == .connected ? "Disconnect" : "Connect") {
                    Task {
                        if model.connectionState == .connected {
                            await model.disconnect()
                        } else {
                            await model.connect()
                        }
                    }
                }
                .disabled(model.isBusy || !canToggleConnection)
                .frame(minWidth: 44, minHeight: 44)
                .accessibilityHint(connectionActionHint)

                if model.enrollment != nil {
                    Button("Leave network", role: .destructive) {
                        showingLeave = true
                    }
                    .disabled(model.isBusy)
                    .accessibilityFocused($focusOnLeave)
                    .frame(minWidth: 44, minHeight: 44)
                }
            }

            Section("Local identity") {
                TextField("Device name", text: $model.preferences.deviceName)
                    .disabled(model.enrollment != nil)
                    .onSubmit { model.savePreferences() }
                    .accessibilityHint("Becomes the stable technical name at enrolment")
                if let address = model.enrollment?.assignedIP {
                    LabeledContent("BlakTail address", value: address)
                        .monospaced()
                        .textSelection(.enabled)
                }
                if let nodeID = model.enrollment?.nodeID {
                    LabeledContent("Node ID", value: nodeID)
                        .monospaced()
                        .textSelection(.enabled)
                }
                if let dnsName = model.localDevice?.dnsName ?? model.enrollment?.dnsName, !dnsName.isEmpty {
                    LabeledContent("MagicDNS", value: dnsName)
                        .monospaced()
                        .textSelection(.enabled)
                }
            }

            Section("Control plane") {
                LabeledContent("Console", value: model.preferences.consoleBaseURL)
                    .textSelection(.enabled)
                if !model.preferences.coordinatorURL.isEmpty {
                    LabeledContent("Coordinator", value: model.preferences.coordinatorURL)
                        .textSelection(.enabled)
                }
            }
        }
        .task(id: model.connectionState) {
            // The tunnel measures its path continuously; poll it while shown.
            while !Task.isCancelled && model.connectionState == .connected {
                await model.refreshTransport()
                try? await Task.sleep(for: .seconds(5))
            }
        }
        .navigationTitle("This iPhone")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.large)
        #endif
        .safeAreaInset(edge: .bottom) { feedback }
        .confirmationDialog(
            "Leave the BlakTail network?",
            isPresented: $showingLeave,
            titleVisibility: .visible
        ) {
            Button("Leave network", role: .destructive) {
                Task {
                    await model.leaveNetwork()
                    try? await Task.sleep(for: .milliseconds(100))
                    focusOnLeave = true
                }
            }
            Button("Cancel", role: .cancel) {
                Task { @MainActor in
                    try? await Task.sleep(for: .milliseconds(100))
                    focusOnLeave = true
                }
            }
        } message: {
            Text("This revokes this iPhone's node credential. Disconnect only pauses the tunnel.")
        }
    }

    private var organisationBinding: Binding<String> {
        Binding(
            get: { model.selectedOrganisation?.id ?? "" },
            set: { model.selectOrganisation($0) }
        )
    }

    private var canToggleConnection: Bool {
        if model.connectionState == .connected { return true }
        if model.enrollment != nil { return true }
        return model.isSignedIn && model.selectedOrganisation?.canMutate == true
    }

    private var connectionActionHint: String {
        if model.connectionState == .connected {
            return "Pauses the local tunnel while retaining enrolment"
        }
        if model.enrollment != nil {
            return "Resumes the saved local enrolment"
        }
        return "Enrols and starts the local BlakTail tunnel"
    }

    private var connectionDescription: String {
        switch model.connectionState {
        case .connected:
            if let network = model.localDevice?.organisationName
                ?? model.enrollment?.organisationName
                ?? model.selectedOrganisation?.name {
                return "Private paths through \(network) are available."
            }
            return "Private paths are available."
        case .connecting:
            return "Creating the local encrypted path."
        case .disconnecting:
            return "Closing the local encrypted path."
        case .disconnected:
            return "This iPhone is not using a BlakTail network."
        }
    }

    private var connectionColour: Color {
        switch model.connectionState {
        case .connected: return .green
        case .connecting, .disconnecting: return .orange
        case .disconnected: return .secondary
        }
    }

    @ViewBuilder
    private var feedback: some View {
        if let error = model.lastError {
            FeedbackBanner(message: error, symbol: "exclamationmark.triangle.fill", isError: true)
        } else if let message = model.feedbackMessage {
            FeedbackBanner(message: message, symbol: "checkmark.circle.fill", isError: false)
        }
    }
}
