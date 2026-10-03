import BlakTailCore
import Foundation

enum WireGuardOutput: Equatable {
    case done
    case writeNetwork(Data, peerPublic: Data)
    case writeTunnel(Data)
    case failed
}

/// Observed relay state reported by the Rust core (`blaktail_relay_status`).
struct RelayStatus: Codable, Equatable {
    var transport: String
    var relay: String?
    var link: String?
    var wssURL: String?
    var healthy: Bool
    var peersDirect: Int
    var peersRelayed: Int
    var failovers: Int

    private enum CodingKeys: String, CodingKey {
        case transport, relay, link, healthy, failovers
        case wssURL = "wss_url"
        case peersDirect = "peers_direct"
        case peersRelayed = "peers_relayed"
    }
}

/// Userspace WireGuard via the in-repo boringtun C ABI. Packets stay ciphertext on the underlay.
final class WireGuardEngine {
    private var tunnel: OpaquePointer

    init(privateKeyBase64: String) throws {
        let raw = try WireGuardKeypair.rawKey(privateKeyBase64)
        let created = raw.withUnsafeBytes { bytes -> OpaquePointer? in
            guard let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            return blaktail_tunnel_create(base)
        }
        guard let created else {
            throw PacketTunnelSessionError.dataplaneUnavailable
        }
        tunnel = created
    }

    deinit {
        blaktail_tunnel_free(tunnel)
    }

    func replacePeers(_ peers: [CoordinatorPeer]) {
        blaktail_tunnel_clear_peers(tunnel)
        for peer in peers {
            guard let key = try? WireGuardKeypair.rawKey(peer.wireGuardPublicKey) else {
                continue
            }
            let allowed = peer.allowedIPs.joined(separator: ",")
            allowed.withCString { allowedPointer in
                key.withUnsafeBytes { bytes in
                    guard let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return
                    }
                    _ = blaktail_tunnel_add_peer(tunnel, base, allowedPointer, 25)
                }
            }
        }
    }

    func encapsulate(_ packet: Data) -> WireGuardOutput {
        invoke { dst, dstLen, peer in
            packet.withUnsafeBytes { bytes in
                blaktail_tunnel_encapsulate(
                    tunnel,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    packet.count,
                    dst,
                    2048,
                    dstLen,
                    peer
                )
            }
        }
    }

    func decapsulate(_ packet: Data) -> WireGuardOutput {
        invoke { dst, dstLen, peer in
            if packet.isEmpty {
                return blaktail_tunnel_decapsulate(tunnel, nil, 0, dst, 2048, dstLen, peer)
            }
            return packet.withUnsafeBytes { bytes in
                blaktail_tunnel_decapsulate(
                    tunnel,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    packet.count,
                    dst,
                    2048,
                    dstLen,
                    peer
                )
            }
        }
    }

    func updateTimers() -> WireGuardOutput {
        invoke { dst, dstLen, peer in
            blaktail_tunnel_update_timers(tunnel, dst, 2048, dstLen, peer)
        }
    }

    func flushNetworkWrites() -> [(Data, Data)] {
        var packets: [(Data, Data)] = []
        for _ in 0..<8 {
            switch decapsulate(Data()) {
            case let .writeNetwork(packet, peerPublic):
                packets.append((packet, peerPublic))
            default:
                return packets
            }
        }
        return packets
    }

    // MARK: Relay fallback (Rust decides; Swift owns the sockets)

    /// Installs the coordinator's relay capability and Australian relay list.
    func configureRelay(selfNodeID: String, snapshot: PeerSnapshot) {
        let relays: [RelayEndpointInfo] = snapshot.relayEndpoints.isEmpty
            // Coordinators that predate declared regions validated their own
            // (Australian) region for every relay; the desktop agent trusts it too.
            ? snapshot.relays.map { RelayEndpointInfo(endpoint: $0, region: "ap-southeast-2") }
            : snapshot.relayEndpoints
        let lines = relays
            .map { "\($0.endpoint)\t\($0.region)\t\($0.wss ?? "")" }
            .joined(separator: "\n")
        _ = blaktail_relay_configure(
            tunnel,
            selfNodeID,
            snapshot.relayToken,
            snapshot.relayExpiresAt,
            lines,
            1
        )
    }

    func setRelayPeers(_ peers: [CoordinatorPeer]) {
        blaktail_relay_begin_peers(tunnel)
        for peer in peers {
            guard let key = try? WireGuardKeypair.rawKey(peer.wireGuardPublicKey) else { continue }
            key.withUnsafeBytes { bytes in
                guard let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                _ = blaktail_relay_set_peer(tunnel, base, peer.id, peer.endpoint == nil ? 0 : 1)
            }
        }
        blaktail_relay_end_peers(tunnel)
    }

    struct RelayRoute {
        var direct: Bool
        var relayFrame: Data?
        var viaWebSocket: Bool
    }

    func route(_ datagram: Data, to peerPublic: Data) -> RelayRoute {
        var output = [UInt8](repeating: 0, count: 2_100)
        var length = 0
        let flags = peerPublic.withUnsafeBytes { key in
            datagram.withUnsafeBytes { source in
                output.withUnsafeMutableBufferPointer { dst in
                    blaktail_relay_outbound(
                        tunnel,
                        key.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        source.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        datagram.count,
                        dst.baseAddress,
                        dst.count,
                        &length
                    )
                }
            }
        }
        if flags < 0 {
            return RelayRoute(direct: true, relayFrame: nil, viaWebSocket: false)
        }
        let relayed = flags & Int32(BLAKTAIL_RELAY_ROUTE_UDP | BLAKTAIL_RELAY_ROUTE_WSS) != 0
        return RelayRoute(
            direct: flags & Int32(BLAKTAIL_RELAY_ROUTE_DIRECT) != 0,
            relayFrame: relayed && length > 0 ? Data(output.prefix(length)) : nil,
            viaWebSocket: flags & Int32(BLAKTAIL_RELAY_ROUTE_WSS) != 0
        )
    }

    /// Unwraps a relay frame into WireGuard ciphertext from a known peer.
    func relayInbound(_ frame: Data, viaWebSocket: Bool, endpoint: String) -> Data? {
        var output = [UInt8](repeating: 0, count: 2_048)
        var length = 0
        var peer = [UInt8](repeating: 0, count: 32)
        let result = frame.withUnsafeBytes { source in
            output.withUnsafeMutableBufferPointer { dst in
                peer.withUnsafeMutableBufferPointer { peerBuffer in
                    blaktail_relay_inbound(
                        tunnel,
                        source.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        frame.count,
                        viaWebSocket ? 1 : 0,
                        endpoint,
                        dst.baseAddress,
                        dst.count,
                        &length,
                        peerBuffer.baseAddress
                    )
                }
            }
        }
        return result == 1 ? Data(output.prefix(length)) : nil
    }

    func directReceived(from peerPublic: Data) {
        peerPublic.withUnsafeBytes { key in
            guard let base = key.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            blaktail_relay_direct_received(tunnel, base)
        }
    }

    enum RelayControl {
        case udp(endpoint: String, frame: Data)
        case webSocket(Data)
    }

    /// Advances relay timers and returns the control frames now due.
    func relayTick() -> [RelayControl] {
        blaktail_relay_tick(tunnel)
        var controls: [RelayControl] = []
        for _ in 0..<16 {
            var frame = [UInt8](repeating: 0, count: 128)
            var length = 0
            var endpoint = [CChar](repeating: 0, count: 256)
            let kind = frame.withUnsafeMutableBufferPointer { dst in
                endpoint.withUnsafeMutableBufferPointer { name in
                    blaktail_relay_poll(tunnel, dst.baseAddress, dst.count, &length, name.baseAddress, name.count)
                }
            }
            let data = Data(frame.prefix(length))
            switch kind {
            case Int32(BLAKTAIL_RELAY_ROUTE_UDP):
                controls.append(.udp(endpoint: String(cString: endpoint), frame: data))
            case Int32(BLAKTAIL_RELAY_ROUTE_WSS):
                controls.append(.webSocket(data))
            default:
                return controls
            }
        }
        return controls
    }

    func relayStatus() -> RelayStatus? {
        var buffer = [CChar](repeating: 0, count: 1_024)
        let length = buffer.withUnsafeMutableBufferPointer { out in
            blaktail_relay_status(tunnel, out.baseAddress, out.count)
        }
        guard length > 0 else { return nil }
        return try? JSONDecoder().decode(RelayStatus.self, from: Data(String(cString: buffer).utf8))
    }

    private func invoke(
        _ body: (UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<Int>, UnsafeMutablePointer<UInt8>) -> Int32
    ) -> WireGuardOutput {
        var output = [UInt8](repeating: 0, count: 2048)
        var length = 0
        var peer = [UInt8](repeating: 0, count: 32)
        let status = output.withUnsafeMutableBufferPointer { dst in
            peer.withUnsafeMutableBufferPointer { peerBuffer in
                body(dst.baseAddress!, &length, peerBuffer.baseAddress!)
            }
        }
        let packet = Data(output.prefix(length))
        let peerPublic = Data(peer)
        switch status {
        case Int32(BLAKTAIL_WG_DONE):
            return .done
        case Int32(BLAKTAIL_WG_WRITE_NETWORK):
            return .writeNetwork(packet, peerPublic: peerPublic)
        case Int32(BLAKTAIL_WG_WRITE_TUNNEL):
            return .writeTunnel(packet)
        default:
            return .failed
        }
    }
}
