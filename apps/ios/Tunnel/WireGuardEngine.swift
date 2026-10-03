import BlakTailCore
import Foundation

enum WireGuardOutput: Equatable {
    case done
    case writeNetwork(Data, peerPublic: Data)
    case writeTunnel(Data)
    case failed
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

    /// Inbound filter policy: the coordinator's raw `peers` array. The filter
    /// runs inside `decapsulate`, between decrypt and the packet-flow write.
    func setPolicy(_ policyJSON: Data) {
        policyJSON.withUnsafeBytes { bytes in
            _ = blaktail_tunnel_set_policy(
                tunnel,
                bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                policyJSON.count
            )
        }
    }

    func setTraffic(_ enabled: Bool) {
        _ = blaktail_tunnel_set_traffic(tunnel, enabled ? 1 : 0)
    }

    /// Coordinator upload body for the counters since the last call, or nil.
    func takeFlowUpload(organisationID: String, deviceID: String, samplingRate: Double) -> Data? {
        var capacity = 64 * 1024
        for _ in 0..<2 {
            var output = [UInt8](repeating: 0, count: capacity)
            var length = 0
            let status = organisationID.withCString { org in
                deviceID.withCString { device in
                    "direct".withCString { transport in
                        output.withUnsafeMutableBufferPointer { buffer in
                            blaktail_tunnel_take_flow_upload(
                                tunnel, org, device, transport, samplingRate,
                                buffer.baseAddress!, capacity, &length
                            )
                        }
                    }
                }
            }
            if status == Int32(BLAKTAIL_WG_DONE) {
                return Data(output.prefix(length))
            }
            guard length > capacity else { return nil }
            capacity = length
        }
        return nil
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
