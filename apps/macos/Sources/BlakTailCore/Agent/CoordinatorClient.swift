import Foundation

public enum CoordinatorClientError: Equatable, LocalizedError, Sendable {
    case invalidURL
    case http(Int, String)
    case decoding
    case unauthorised
    case insecureURL

    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "The coordinator URL is not valid."
        case .http(let code, let body):
            return "Coordinator returned \(code): \(body)"
        case .decoding:
            return "Could not read the coordinator response."
        case .unauthorised:
            return "This iPhone's node credential was rejected. Enrol again."
        case .insecureURL:
            return "The coordinator must use HTTPS (HTTP is allowed only for localhost)."
        }
    }
}

/// Talks to the onshore coordinator using the same register/peers/revoke contract as `blaktaild`.
public struct CoordinatorClient: Sendable {
    public var baseURL: URL
    public var urlSession: URLSession

    public init(baseURL: URL, urlSession: URLSession = .shared) throws {
        self.baseURL = try Self.validated(baseURL)
        self.urlSession = urlSession
    }

    public init(coordinator: String, urlSession: URLSession = .shared) throws {
        guard let url = URL(string: coordinator) else {
            throw CoordinatorClientError.invalidURL
        }
        try self.init(baseURL: url, urlSession: urlSession)
    }

    public func register(
        joinKey: String,
        name: String,
        publicKey: String,
        organisationID: String,
        organisationName: String
    ) async throws -> NodeEnrollment {
        let payload = try JSONSerialization.data(withJSONObject: [
            "join_key": joinKey,
            "name": name,
            "wg_public_key": publicKey,
            "allowed_ips": [String](),
            "advertised_routes": [String](),
            "os": "ios",
            "os_version": osVersion,
            "agent_version": BlakTailIdentifiers.agentVersion,
            "hostname": name,
            "capabilities": ["wireguard", "magicdns"],
            "ephemeral": false
        ])
        let (data, response) = try await request(
            path: "/v1/nodes/register",
            method: "POST",
            body: payload,
            bearer: nil
        )
        try validate(response: response, data: data)
        let decoded = try decode(RegisterResponse.self, from: data)
        let assignedIPs = decoded.assignedIps.isEmpty ? [decoded.assignedIp] : decoded.assignedIps
        return NodeEnrollment(
            nodeID: decoded.id,
            nodeToken: decoded.nodeToken,
            coordinatorURL: baseURL.absoluteString,
            organisationID: organisationID,
            organisationName: organisationName,
            deviceName: name,
            assignedIP: decoded.assignedIp,
            assignedIPs: assignedIPs,
            dnsName: decoded.dnsName,
            credentialExpiresAt: decoded.credentialExpiresAt,
            wireGuardPrivateKey: "",
            wireGuardPublicKey: publicKey,
            relays: decoded.relays,
            relayToken: decoded.relayToken,
            relayExpiresAt: decoded.relayExpiresAt
        )
    }

    /// `capabilities` reports what this client enforces (for example
    /// `acl-filter` from the packet tunnel, whose dataplane filters inbound).
    public func peers(enrollment: NodeEnrollment, capabilities: [String] = []) async throws -> PeerSnapshot {
        var query = [URLQueryItem(name: "ipv6", value: "true")]
        if !capabilities.isEmpty {
            query.append(URLQueryItem(name: "capabilities", value: capabilities.joined(separator: ",")))
        }
        let (data, response) = try await request(
            path: "/v1/nodes/\(enrollment.nodeID)/peers",
            method: "GET",
            body: nil,
            bearer: enrollment.nodeToken,
            query: query
        )
        try validate(response: response, data: data)
        let decoded = try decode(PeersResponse.self, from: data)
        var policy = Data("[]".utf8)
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let peers = object["peers"],
           let encoded = try? JSONSerialization.data(withJSONObject: peers) {
            policy = encoded
        }
        return PeerSnapshot(
            peers: decoded.peers,
            assignedIPs: decoded.assignedIps,
            dnsName: decoded.dnsName,
            credentialExpiresAt: decoded.credentialExpiresAt,
            relays: decoded.relays,
            relayToken: decoded.relayToken,
            relayExpiresAt: decoded.relayExpiresAt,
            policyJSON: policy,
            traffic: decoded.traffic
        )
    }

    /// Uploads one aggregate traffic batch built by the native dataplane.
    /// Returns false when the coordinator says diagnostics are off.
    public func uploadFlows(enrollment: NodeEnrollment, body: Data) async throws -> Bool {
        let (data, response) = try await request(
            path: "/v1/nodes/\(enrollment.nodeID)/flows",
            method: "POST",
            body: body,
            bearer: enrollment.nodeToken
        )
        if let http = response as? HTTPURLResponse, http.statusCode == 409,
           sanitizedErrorBody(data).contains("turned off") {
            return false
        }
        try validate(response: response, data: data)
        return true
    }

    public func revoke(enrollment: NodeEnrollment) async throws {
        let (data, response) = try await request(
            path: "/v1/nodes/\(enrollment.nodeID)",
            method: "DELETE",
            body: nil,
            bearer: enrollment.nodeToken
        )
        try validate(response: response, data: data)
    }

    public static func validated(_ url: URL) throws -> URL {
        guard let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty
        else {
            throw CoordinatorClientError.invalidURL
        }
        let localhost = host == "127.0.0.1" || host == "localhost"
        if scheme == "https" || (scheme == "http" && localhost) {
            return url
        }
        throw CoordinatorClientError.insecureURL
    }

    private var osVersion: String {
        #if os(iOS)
        ProcessInfo.processInfo.operatingSystemVersionString
        #else
        "ios"
        #endif
    }

    private func request(
        path: String,
        method: String,
        body: Data?,
        bearer: String?,
        query: [URLQueryItem] = []
    ) async throws -> (Data, URLResponse) {
        let trimmed = path.hasPrefix("/") ? String(path.dropFirst()) : path
        var components = URLComponents(
            url: baseURL.appending(path: trimmed),
            resolvingAgainstBaseURL: false
        )
        if !query.isEmpty {
            components?.queryItems = query
        }
        guard let url = components?.url else {
            throw CoordinatorClientError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let bearer, !bearer.isEmpty {
            request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return try await urlSession.data(for: request)
    }

    private func validate(response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else {
            throw CoordinatorClientError.decoding
        }
        if http.statusCode == 401 || http.statusCode == 403 {
            throw CoordinatorClientError.unauthorised
        }
        guard (200..<300).contains(http.statusCode) else {
            throw CoordinatorClientError.http(
                http.statusCode,
                sanitizedErrorBody(data)
            )
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        guard let value = try? JSONDecoder().decode(type, from: data) else {
            throw CoordinatorClientError.decoding
        }
        return value
    }

    private func sanitizedErrorBody(_ data: Data) -> String {
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String {
            return error
        }
        let raw = String(data: data, encoding: .utf8) ?? ""
        if raw.localizedCaseInsensitiveContains("btk_") || raw.localizedCaseInsensitiveContains("btn_") {
            return "request rejected"
        }
        return raw
    }

    private struct RegisterResponse: Decodable {
        var id: String
        var nodeToken: String
        var assignedIp: String
        var assignedIps: [String]
        var dnsName: String
        var credentialExpiresAt: Int
        var relays: [String]
        var relayToken: String
        var relayExpiresAt: UInt64

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.decode(String.self, forKey: .id)
            nodeToken = try container.decode(String.self, forKey: .nodeToken)
            assignedIp = try container.decode(String.self, forKey: .assignedIp)
            assignedIps = try container.decodeIfPresent([String].self, forKey: .assignedIps) ?? []
            dnsName = try container.decodeIfPresent(String.self, forKey: .dnsName) ?? ""
            credentialExpiresAt = try container.decodeIfPresent(Int.self, forKey: .credentialExpiresAt) ?? 0
            relays = try container.decodeIfPresent([String].self, forKey: .relays) ?? []
            relayToken = try container.decodeIfPresent(String.self, forKey: .relayToken) ?? ""
            relayExpiresAt = try container.decodeIfPresent(UInt64.self, forKey: .relayExpiresAt) ?? 0
        }

        private enum CodingKeys: String, CodingKey {
            case id
            case nodeToken = "node_token"
            case assignedIp = "assigned_ip"
            case assignedIps = "assigned_ips"
            case dnsName = "dns_name"
            case credentialExpiresAt = "credential_expires_at"
            case relays
            case relayToken = "relay_token"
            case relayExpiresAt = "relay_expires_at"
        }
    }

    private struct PeersResponse: Decodable {
        var traffic: TrafficReporting?
        var peers: [CoordinatorPeer]
        var assignedIps: [String]
        var dnsName: String
        var credentialExpiresAt: Int
        var relays: [String]
        var relayToken: String
        var relayExpiresAt: UInt64

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            traffic = try? container.decodeIfPresent(TrafficReporting.self, forKey: .traffic)
            peers = try container.decodeIfPresent([CoordinatorPeer].self, forKey: .peers) ?? []
            assignedIps = try container.decodeIfPresent([String].self, forKey: .assignedIps) ?? []
            dnsName = try container.decodeIfPresent(String.self, forKey: .dnsName) ?? ""
            credentialExpiresAt = try container.decodeIfPresent(Int.self, forKey: .credentialExpiresAt) ?? 0
            relays = try container.decodeIfPresent([String].self, forKey: .relays) ?? []
            relayToken = try container.decodeIfPresent(String.self, forKey: .relayToken) ?? ""
            relayExpiresAt = try container.decodeIfPresent(UInt64.self, forKey: .relayExpiresAt) ?? 0
        }

        private enum CodingKeys: String, CodingKey {
            case traffic
            case peers
            case assignedIps = "assigned_ips"
            case dnsName = "dns_name"
            case credentialExpiresAt = "credential_expires_at"
            case relays
            case relayToken = "relay_token"
            case relayExpiresAt = "relay_expires_at"
        }
    }
}
