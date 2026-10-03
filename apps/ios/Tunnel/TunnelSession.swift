import BlakTailCore
import Foundation
import Network
import NetworkExtension

enum PacketTunnelSessionError: LocalizedError {
    case missingEnrollment
    case dataplaneUnavailable
    case invalidAddress

    var errorDescription: String? {
        switch self {
        case .missingEnrollment:
            return "This iPhone has no saved BlakTail enrolment."
        case .dataplaneUnavailable:
            return "The WireGuard dataplane could not be created."
        case .invalidAddress:
            return "The coordinator returned an invalid overlay address."
        }
    }
}

@MainActor
final class TunnelSession {
    private let provider: NEPacketTunnelProvider
    private var enrollment: NodeEnrollment
    private var engine: WireGuardEngine
    private var peers: [CoordinatorPeer] = []
    private var sessions: [Data: NWUDPSession] = [:]
    private var pollTask: Task<Void, Never>?
    private var timerTask: Task<Void, Never>?
    private var dns: MagicDNSResponder
    private var traffic: TrafficReporting?
    private var lastTrafficUpload = Date()
    /// The dataplane filters inbound packets, so the coordinator may report
    /// this phone's ports as enforced.
    private static let capabilities = ["wireguard", "magicdns", "acl-filter"]

    init(provider: NEPacketTunnelProvider) throws {
        guard let enrollment = try EnrollmentStore().load() else {
            throw PacketTunnelSessionError.missingEnrollment
        }
        self.provider = provider
        self.enrollment = enrollment
        engine = try WireGuardEngine(privateKeyBase64: enrollment.wireGuardPrivateKey)
        dns = MagicDNSResponder(enrollment: enrollment, peers: [])
    }

    func start() async throws {
        let snapshot = try await CoordinatorClient(coordinator: enrollment.coordinatorURL)
            .peers(enrollment: enrollment, capabilities: Self.capabilities)
        apply(snapshot)
        try await provider.setTunnelNetworkSettings(networkSettings())
        readPackets()
        kickHandshake()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                await self?.refreshPeers()
            }
        }
        timerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                self?.pollTimers()
            }
        }
    }

    func stop() {
        pollTask?.cancel()
        timerTask?.cancel()
        sessions.values.forEach { $0.cancel() }
        sessions.removeAll()
    }

    private func apply(_ snapshot: PeerSnapshot) {
        if !snapshot.assignedIPs.isEmpty {
            enrollment.assignedIPs = snapshot.assignedIPs
            enrollment.assignedIP = snapshot.assignedIPs[0]
        }
        if !snapshot.dnsName.isEmpty {
            enrollment.dnsName = snapshot.dnsName
        }
        enrollment.credentialExpiresAt = snapshot.credentialExpiresAt
        peers = snapshot.peers
        engine.replacePeers(peers)
        engine.setPolicy(snapshot.policyJSON)
        applyTraffic(snapshot.traffic)
        dns = MagicDNSResponder(enrollment: enrollment, peers: peers)
        for peer in peers {
            ensureSession(for: peer)
        }
    }

    private func refreshPeers() async {
        do {
            let snapshot = try await CoordinatorClient(coordinator: enrollment.coordinatorURL)
                .peers(enrollment: enrollment, capabilities: Self.capabilities)
            apply(snapshot)
            try await provider.setTunnelNetworkSettings(networkSettings())
        } catch {
            // Keep the existing tunnel configuration if the coordinator is briefly unavailable.
        }
        await uploadTraffic()
    }

    /// Counting runs only while the peer map says diagnostics are on; turning
    /// it off discards counters immediately.
    private func applyTraffic(_ setting: TrafficReporting?) {
        let active = setting.flatMap { $0.enabled && $0.samplingRate > 0 ? $0 : nil }
        if active != nil && traffic == nil {
            lastTrafficUpload = Date()
        }
        traffic = active
        engine.setTraffic(active != nil)
    }

    private func uploadTraffic() async {
        guard let traffic, Date().timeIntervalSince(lastTrafficUpload) >= 60 else { return }
        lastTrafficUpload = Date()
        guard let body = engine.takeFlowUpload(
            organisationID: traffic.organisationID,
            deviceID: enrollment.nodeID,
            samplingRate: traffic.samplingRate
        ), !body.isEmpty, body != Data(#"{"records":[]}"#.utf8) else { return }
        do {
            let accepted = try await CoordinatorClient(coordinator: enrollment.coordinatorURL)
                .uploadFlows(enrollment: enrollment, body: body)
            if !accepted {
                applyTraffic(nil)
            }
        } catch {
            // Counters for this bucket are dropped; reporting is best effort.
        }
    }

    private func readPackets() {
        provider.packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            Task { @MainActor in
                for packet in packets {
                    self.handleInnerPacket(packet)
                }
                self.readPackets()
            }
        }
    }

    private func handleInnerPacket(_ packet: Data) {
        if let dnsReply = dnsReply(for: packet) {
            provider.packetFlow.writePackets([dnsReply], withProtocols: [AF_INET as NSNumber])
            return
        }
        switch engine.encapsulate(packet) {
        case let .writeNetwork(datagram, peerPublic):
            send(datagram, to: peerPublic)
        default:
            break
        }
    }

    private func handleRemoteDatagram(_ datagram: Data) {
        switch engine.decapsulate(datagram) {
        case let .writeTunnel(inner):
            let version = inner.first.map { $0 >> 4 } ?? 4
            let protocolNumber = NSNumber(value: version == 6 ? AF_INET6 : AF_INET)
            provider.packetFlow.writePackets([inner], withProtocols: [protocolNumber])
        case let .writeNetwork(reply, peerPublic):
            send(reply, to: peerPublic)
        default:
            break
        }
        for (packet, peerPublic) in engine.flushNetworkWrites() {
            send(packet, to: peerPublic)
        }
    }

    private func pollTimers() {
        switch engine.updateTimers() {
        case let .writeNetwork(datagram, peerPublic):
            send(datagram, to: peerPublic)
        default:
            break
        }
    }

    private func kickHandshake() {
        pollTimers()
    }

    private func send(_ datagram: Data, to peerPublic: Data) {
        if let session = sessions[peerPublic] {
            session.writeDatagram(datagram) { _ in }
            return
        }
        if let peer = peers.first(where: {
            (try? WireGuardKeypair.rawKey($0.wireGuardPublicKey)) == peerPublic
        }) {
            ensureSession(for: peer)
            sessions[peerPublic]?.writeDatagram(datagram) { _ in }
        }
    }

    private func ensureSession(for peer: CoordinatorPeer) {
        guard let key = try? WireGuardKeypair.rawKey(peer.wireGuardPublicKey) else { return }
        if sessions[key] != nil { return }
        guard let endpoint = peer.endpoint, let parsed = parseEndpoint(endpoint) else { return }
        let session = provider.createUDPSession(
            to: NWHostEndpoint(hostname: parsed.host, port: parsed.port),
            from: nil
        )
        session.setReadHandler({ [weak self] datagrams, _ in
            guard let self else { return }
            Task { @MainActor in
                for datagram in datagrams ?? [] {
                    self.handleRemoteDatagram(datagram)
                }
            }
        }, maxDatagrams: 32)
        sessions[key] = session
    }

    private func parseEndpoint(_ endpoint: String) -> (host: String, port: String)? {
        if endpoint.hasPrefix("["), let close = endpoint.firstIndex(of: "]") {
            let host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<close])
            let rest = endpoint[endpoint.index(after: close)...]
            guard rest.first == ":", rest.count > 1 else { return nil }
            return (host, String(rest.dropFirst()))
        }
        guard let colon = endpoint.lastIndex(of: ":") else { return nil }
        return (String(endpoint[..<colon]), String(endpoint[endpoint.index(after: colon)...]))
    }

    private func networkSettings() throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: BlakTailIdentifiers.tunnelMTU)

        let ipv4 = enrollment.interfaceAddresses.filter { !$0.contains(":") }
        if let first = ipv4.first, let parsed = Self.splitCIDR(first) {
            let ipv4Settings = NEIPv4Settings(
                addresses: [parsed.address],
                subnetMasks: [Self.ipv4Mask(prefix: parsed.prefix)]
            )
            ipv4Settings.includedRoutes = peers.flatMap(\.allowedIPs).compactMap { cidr -> NEIPv4Route? in
                guard !cidr.contains(":"), let route = Self.splitCIDR(cidr) else { return nil }
                return NEIPv4Route(
                    destinationAddress: route.address,
                    subnetMask: Self.ipv4Mask(prefix: route.prefix)
                )
            }
            settings.ipv4Settings = ipv4Settings
            if let domain = MagicDNS.domain(from: enrollment.dnsName) {
                let dnsSettings = NEDNSSettings(servers: [parsed.address])
                dnsSettings.matchDomains = [domain]
                dnsSettings.searchDomains = [domain]
                settings.dnsSettings = dnsSettings
            }
        }

        let ipv6 = enrollment.interfaceAddresses.filter { $0.contains(":") }
        if let first = ipv6.first, let parsed = Self.splitCIDR(first) {
            let ipv6Settings = NEIPv6Settings(
                addresses: [parsed.address],
                networkPrefixLengths: [NSNumber(value: parsed.prefix)]
            )
            ipv6Settings.includedRoutes = peers.flatMap(\.allowedIPs).compactMap { cidr -> NEIPv6Route? in
                guard cidr.contains(":"), let route = Self.splitCIDR(cidr) else { return nil }
                return NEIPv6Route(
                    destinationAddress: route.address,
                    networkPrefixLength: NSNumber(value: route.prefix)
                )
            }
            settings.ipv6Settings = ipv6Settings
        }
        return settings
    }

    private func dnsReply(for packet: Data) -> Data? {
        guard packet.count >= 28, packet[0] >> 4 == 4 else { return nil }
        let protocolNumber = packet[9]
        guard protocolNumber == 17 else { return nil }
        let dest = String(format: "%d.%d.%d.%d", packet[16], packet[17], packet[18], packet[19])
        let destPort = Int(packet[22]) << 8 | Int(packet[23])
        guard destPort == 53 else { return nil }
        guard let own = Self.splitCIDR(enrollment.assignedIP)?.address, own == dest else { return nil }
        let ihl = Int(packet[0] & 0x0F) * 4
        guard packet.count >= ihl + 8 else { return nil }
        let query = Data(packet[(ihl + 8)...])
        guard let answer = dns.answer(query: query) else { return nil }
        return Self.ipv4UDPReply(request: packet, payload: answer)
    }

    private static func ipv4UDPReply(request: Data, payload: Data) -> Data? {
        guard request.count >= 28 else { return nil }
        let ihl = Int(request[0] & 0x0F) * 4
        var packet = Data(count: ihl + 8 + payload.count)
        packet[0] = request[0]
        let total = UInt16(packet.count)
        packet[2] = UInt8(total >> 8)
        packet[3] = UInt8(total & 0xFF)
        packet[8] = 64
        packet[9] = 17
        packet.replaceSubrange(12..<16, with: request[16..<20])
        packet.replaceSubrange(16..<20, with: request[12..<16])
        packet.replaceSubrange(ihl..<(ihl + 2), with: request[(ihl + 2)..<(ihl + 4)])
        packet.replaceSubrange((ihl + 2)..<(ihl + 4), with: request[ihl..<(ihl + 2)])
        let udpLength = UInt16(8 + payload.count)
        packet[ihl + 4] = UInt8(udpLength >> 8)
        packet[ihl + 5] = UInt8(udpLength & 0xFF)
        packet.replaceSubrange((ihl + 8)..., with: payload)
        return packet
    }

    private static func splitCIDR(_ value: String) -> (address: String, prefix: Int)? {
        let parts = value.split(separator: "/", maxSplits: 1).map(String.init)
        guard let address = parts.first, !address.isEmpty else { return nil }
        let prefix = parts.count == 2 ? Int(parts[1]) : (address.contains(":") ? 128 : 32)
        guard let prefix, prefix >= 0, prefix <= (address.contains(":") ? 128 : 32) else {
            return nil
        }
        return (address, prefix)
    }

    private static func ipv4Mask(prefix: Int) -> String {
        let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
        return "\((mask >> 24) & 0xFF).\((mask >> 16) & 0xFF).\((mask >> 8) & 0xFF).\(mask & 0xFF)"
    }
}
