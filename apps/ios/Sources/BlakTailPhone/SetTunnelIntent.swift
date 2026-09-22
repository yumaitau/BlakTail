#if os(iOS)
import AppIntents
import BlakTailCore

public struct SetTunnelIntent: AppIntent {
    public static var title: LocalizedStringResource = "Set the BlakTail tunnel"
    public static var description = IntentDescription("Connects or disconnects this iPhone.")
    public static var openAppWhenRun = false

    @Parameter(title: "Connected")
    public var connected: Bool

    public init() {
        connected = false
    }

    public init(connected: Bool) {
        self.connected = connected
    }

    public func perform() async throws -> some IntentResult {
        guard let enrollment = try EnrollmentStore().load() else {
            PhoneWidgetStore.save(
                PhoneWidgetSnapshot(
                    label: "Join in the app",
                    organisation: "",
                    address: "",
                    connected: false,
                    enrolled: false
                )
            )
            return .result()
        }
        let tunnel = PacketTunnelController.system
        if connected {
            try await tunnel.start()
        } else {
            try await tunnel.stop()
        }
        let running = await tunnel.isRunning()
        PhoneWidgetStore.save(
            PhoneWidgetSnapshot(
                label: running ? ConnectionState.connected.label : ConnectionState.disconnected.label,
                organisation: enrollment.organisationName,
                address: enrollment.assignedIP,
                connected: running,
                enrolled: true
            )
        )
        return .result()
    }
}
#endif
