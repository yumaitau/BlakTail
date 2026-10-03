import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var session: TunnelSession?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let session = try TunnelSession(provider: self)
                try await session.start()
                self.session = session
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }

    /// The app asks for observed transport (direct, relay, relay-wss).
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        Task { @MainActor in
            completionHandler?(session?.statusJSON())
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        Task { @MainActor in
            session?.stop()
            session = nil
            completionHandler()
        }
    }
}
