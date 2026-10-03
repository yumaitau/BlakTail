import BlakTailCore
import Foundation

public protocol PacketTunnelControlling: Sendable {
    func start() async throws
    func stop() async throws
    func isRunning() async -> Bool
    /// Observed data path reported by the running packet tunnel.
    func transportStatus() async -> TunnelTransportStatus?
}

public extension PacketTunnelControlling {
    func transportStatus() async -> TunnelTransportStatus? { nil }
}

/// What the packet tunnel last measured. `transport` is `direct`, `relay`
/// (Australian relay over UDP), `relay-wss` (the HTTPS fallback) or `none`.
public struct TunnelTransportStatus: Decodable, Equatable, Sendable {
    public var transport: String
    public var relay: String?
    public var healthy: Bool
    public var peersDirect: Int
    public var peersRelayed: Int

    public init(transport: String, relay: String? = nil, healthy: Bool = false, peersDirect: Int = 0, peersRelayed: Int = 0) {
        self.transport = transport
        self.relay = relay
        self.healthy = healthy
        self.peersDirect = peersDirect
        self.peersRelayed = peersRelayed
    }

    public var label: String {
        switch transport {
        case "direct": return "Direct"
        case "relay": return "Australian relay"
        case "relay-wss": return "Australian relay over HTTPS"
        default: return "No active peers yet"
        }
    }

    public var detail: String {
        switch transport {
        case "relay", "relay-wss":
            let fallback = transport == "relay-wss"
                ? " UDP is blocked on this network, so encrypted traffic uses port 443."
                : ""
            return "\(peersRelayed) relayed, \(peersDirect) direct. Traffic stays WireGuard-encrypted.\(fallback)"
        case "direct":
            return "\(peersDirect) peers reached without a relay."
        default:
            return "The path is measured once traffic flows."
        }
    }

    private enum CodingKeys: String, CodingKey {
        case transport, relay, healthy
        case peersDirect = "peers_direct"
        case peersRelayed = "peers_relayed"
    }
}

public enum PacketTunnelController {
    public static var system: any PacketTunnelControlling {
        #if os(iOS)
        SystemPacketTunnelController()
        #else
        UnavailablePacketTunnelController()
        #endif
    }
}

public struct UnavailablePacketTunnelController: PacketTunnelControlling {
    public init() {}

    public func start() async throws {
        throw PacketTunnelControllerError.unavailable
    }

    public func stop() async throws {}

    public func isRunning() async -> Bool { false }
}

public enum PacketTunnelControllerError: LocalizedError, Sendable {
    case unavailable
    case startFailed

    public var errorDescription: String? {
        switch self {
        case .unavailable:
            return "This host cannot start the iPhone packet tunnel."
        case .startFailed:
            return "Could not start the BlakTail packet tunnel."
        }
    }
}

#if os(iOS)
import NetworkExtension

public struct SystemPacketTunnelController: PacketTunnelControlling {
    public init() {}

    public func start() async throws {
        let manager = try await loadOrCreate()
        if !manager.isEnabled {
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        }
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            throw PacketTunnelControllerError.startFailed
        }
    }

    public func stop() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        managers.first?.connection.stopVPNTunnel()
    }

    public func isRunning() async -> Bool {
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        return managers.contains { $0.connection.status == .connected }
    }

    public func transportStatus() async -> TunnelTransportStatus? {
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        guard let session = managers.first(where: { $0.connection.status == .connected })?
            .connection as? NETunnelProviderSession else {
            return nil
        }
        let reply: Data? = await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(Data("transport".utf8)) { continuation.resume(returning: $0) }
            } catch {
                continuation.resume(returning: nil)
            }
        }
        guard let reply else { return nil }
        return try? JSONDecoder().decode(TunnelTransportStatus.self, from: reply)
    }

    private func loadOrCreate() async throws -> NETunnelProviderManager {
        let existing = try await NETunnelProviderManager.loadAllFromPreferences()
        let manager = existing.first ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = BlakTailIdentifiers.tunnelBundleID
        proto.serverAddress = "BlakTail"
        proto.disconnectOnSleep = false
        manager.localizedDescription = "BlakTail"
        manager.protocolConfiguration = proto
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        return manager
    }
}
#endif
