import Foundation

/// Persisted phone node identity. The join key is never stored here.
public struct NodeEnrollment: Codable, Equatable, Sendable {
    public var nodeID: String
    public var nodeToken: String
    public var coordinatorURL: String
    public var organisationID: String
    public var organisationName: String
    public var deviceName: String
    public var assignedIP: String
    public var assignedIPs: [String]
    public var dnsName: String
    public var credentialExpiresAt: Int
    public var wireGuardPrivateKey: String
    public var wireGuardPublicKey: String
    public var relays: [String]
    public var relayToken: String
    public var relayExpiresAt: UInt64

    public init(
        nodeID: String,
        nodeToken: String,
        coordinatorURL: String,
        organisationID: String,
        organisationName: String,
        deviceName: String,
        assignedIP: String,
        assignedIPs: [String],
        dnsName: String,
        credentialExpiresAt: Int,
        wireGuardPrivateKey: String,
        wireGuardPublicKey: String,
        relays: [String] = [],
        relayToken: String = "",
        relayExpiresAt: UInt64 = 0
    ) {
        self.nodeID = nodeID
        self.nodeToken = nodeToken
        self.coordinatorURL = coordinatorURL
        self.organisationID = organisationID
        self.organisationName = organisationName
        self.deviceName = deviceName
        self.assignedIP = assignedIP
        self.assignedIPs = assignedIPs
        self.dnsName = dnsName
        self.credentialExpiresAt = credentialExpiresAt
        self.wireGuardPrivateKey = wireGuardPrivateKey
        self.wireGuardPublicKey = wireGuardPublicKey
        self.relays = relays
        self.relayToken = relayToken
        self.relayExpiresAt = relayExpiresAt
    }

    public var interfaceAddresses: [String] {
        var addresses = assignedIPs
        if !assignedIP.isEmpty, !addresses.contains(assignedIP) {
            addresses.insert(assignedIP, at: 0)
        }
        return addresses.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }

    /// Safe for UI and logs. Tokens and private keys stay out.
    public var redactedDescription: String {
        let address = assignedIP.isEmpty ? dnsName : assignedIP
        return "node \(nodeID) \(address)"
    }

    public var containsJoinKey: Bool {
        nodeToken.lowercased().contains("btk_")
            || wireGuardPrivateKey.lowercased().contains("btk_")
            || coordinatorURL.lowercased().contains("btk_")
    }
}

public struct CoordinatorPeer: Codable, Equatable, Hashable, Identifiable, Sendable {
    public var id: String
    public var name: String
    public var wireGuardPublicKey: String
    public var endpoint: String?
    public var allowedIPs: [String]
    public var dnsName: String
    public var tags: [String]
    public var relayEndpoint: String?

    public init(
        id: String,
        name: String,
        wireGuardPublicKey: String,
        endpoint: String?,
        allowedIPs: [String],
        dnsName: String,
        tags: [String] = [],
        relayEndpoint: String? = nil
    ) {
        self.id = id
        self.name = name
        self.wireGuardPublicKey = wireGuardPublicKey
        self.endpoint = endpoint
        self.allowedIPs = allowedIPs
        self.dnsName = dnsName
        self.tags = tags
        self.relayEndpoint = relayEndpoint
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case wireGuardPublicKey = "wg_public_key"
        case endpoint
        case allowedIPs = "allowed_ips"
        case dnsName = "dns_name"
        case tags
        case relayEndpoint = "relay_endpoint"
    }
}

/// The organisation's traffic diagnostics setting as the peer map carries it.
/// Absent means off.
public struct TrafficReporting: Codable, Equatable, Sendable {
    public var enabled: Bool
    public var samplingRate: Double
    public var organisationID: String

    public init(enabled: Bool, samplingRate: Double, organisationID: String) {
        self.enabled = enabled
        self.samplingRate = samplingRate
        self.organisationID = organisationID
    }

    private enum CodingKeys: String, CodingKey {
        case enabled
        case samplingRate = "sampling_rate"
        case organisationID = "org_id"
    }
}

public struct PeerSnapshot: Equatable, Sendable {
    public var peers: [CoordinatorPeer]
    public var assignedIPs: [String]
    public var dnsName: String
    public var credentialExpiresAt: Int
    public var relays: [String]
    public var relayToken: String
    public var relayExpiresAt: UInt64
    /// The raw `peers` array (with each peer's `ingress` grants) for the
    /// native inbound filter.
    public var policyJSON: Data
    public var traffic: TrafficReporting?

    public init(
        peers: [CoordinatorPeer],
        assignedIPs: [String],
        dnsName: String,
        credentialExpiresAt: Int,
        relays: [String] = [],
        relayToken: String = "",
        relayExpiresAt: UInt64 = 0,
        policyJSON: Data = Data("[]".utf8),
        traffic: TrafficReporting? = nil
    ) {
        self.peers = peers
        self.assignedIPs = assignedIPs
        self.dnsName = dnsName
        self.credentialExpiresAt = credentialExpiresAt
        self.relays = relays
        self.relayToken = relayToken
        self.relayExpiresAt = relayExpiresAt
        self.policyJSON = policyJSON
        self.traffic = traffic
    }
}

public enum MagicDNS {
    public static func domain(from dnsName: String) -> String? {
        let trimmed = dnsName.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard let index = trimmed.firstIndex(of: ".") else { return nil }
        let domain = String(trimmed[trimmed.index(after: index)...]).lowercased()
        return isValidDomain(domain) ? domain : nil
    }

    public static func hostLabel(from dnsName: String) -> String? {
        let trimmed = dnsName.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard let index = trimmed.firstIndex(of: ".") else { return nil }
        let label = String(trimmed[..<index]).lowercased()
        return label.isEmpty ? nil : label
    }

    private static func isValidDomain(_ domain: String) -> Bool {
        !domain.isEmpty
            && domain.count <= 253
            && domain.hasSuffix(".blaktail")
            && domain.split(separator: ".").allSatisfy { label in
                !label.isEmpty
                    && label.count <= 63
                    && !label.hasPrefix("-")
                    && !label.hasSuffix("-")
                    && label.unicodeScalars.allSatisfy {
                        CharacterSet.alphanumerics.contains($0) || $0 == "-"
                    }
            }
    }
}

public struct EnrollmentStore: Sendable {
    public var secrets: any SecretStoring

    public init(secrets: any SecretStoring = KeychainStore.phoneEnrollment) {
        self.secrets = secrets
    }

    public init(keychain: KeychainStore) {
        self.init(secrets: keychain)
    }

    public func save(_ enrollment: NodeEnrollment) throws {
        let data = try JSONEncoder().encode(enrollment)
        guard let json = String(data: data, encoding: .utf8) else {
            throw CoordinatorClientError.decoding
        }
        try secrets.save(json)
    }

    public func load() throws -> NodeEnrollment? {
        guard let json = try secrets.load(), !json.isEmpty else {
            return nil
        }
        return try JSONDecoder().decode(NodeEnrollment.self, from: Data(json.utf8))
    }

    public func delete() throws {
        try secrets.delete()
    }
}
