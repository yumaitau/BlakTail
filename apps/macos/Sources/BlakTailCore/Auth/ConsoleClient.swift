import Foundation

public struct DesktopOrganisation: Codable, Equatable, Hashable, Identifiable, Sendable {
    public var id: String
    public var name: String
    public var role: String

    public init(id: String, name: String, role: String) {
        self.id = id
        self.name = name
        self.role = role
    }

    public var canMutate: Bool { role == "owner" || role == "admin" }
}

public struct DesktopSession: Equatable, Sendable {
    public var email: String
    public var organisationID: String
    public var organisationName: String
    public var role: String
    public var organisations: [DesktopOrganisation]
    public var coordinatorURL: String?

    public init(
        email: String,
        organisationID: String = "",
        organisationName: String,
        role: String,
        organisations: [DesktopOrganisation] = [],
        coordinatorURL: String?
    ) {
        self.email = email
        self.organisationID = organisationID
        self.organisationName = organisationName
        self.role = role
        self.organisations = organisations
        self.coordinatorURL = coordinatorURL
    }
}

public enum EndpointCredentialState: String, Equatable, Sendable {
    case active
    case expiresSoon
    case expired
    case revoked

    public var label: String {
        switch self {
        case .active: return "Active"
        case .expiresSoon: return "Expires soon"
        case .expired: return "Expired"
        case .revoked: return "Revoked"
        }
    }

    public var symbol: String {
        switch self {
        case .active: return "checkmark.circle.fill"
        case .expiresSoon: return "clock.badge.exclamationmark"
        case .expired: return "clock.badge.xmark"
        case .revoked: return "xmark.octagon.fill"
        }
    }
}

public struct EndpointDevice: Codable, Equatable, Hashable, Identifiable, Sendable {
    public var nodeID: String
    public var technicalName: String
    public var friendlyName: String?
    public var wireGuardPublicKey: String
    public var endpoint: String?
    public var allowedIPs: [String]
    public var advertisedRoutes: [String]
    public var approvedRoutes: [String]
    public var dnsName: String
    public var tags: [String]
    public var createdAt: Int
    public var credentialExpiresAt: Int
    public var expired: Bool
    public var expiresSoon: Bool
    public var revoked: Bool
    public var organisationID: String
    public var organisationName: String
    public var canMutate: Bool

    public var id: String { "\(organisationID):\(nodeID)" }
    public var displayName: String { friendlyName ?? technicalName }
    public var credentialState: EndpointCredentialState {
        if revoked { return .revoked }
        if expired { return .expired }
        if expiresSoon { return .expiresSoon }
        return .active
    }

    public init(
        nodeID: String,
        technicalName: String,
        friendlyName: String?,
        wireGuardPublicKey: String,
        endpoint: String?,
        allowedIPs: [String],
        advertisedRoutes: [String],
        approvedRoutes: [String],
        dnsName: String,
        tags: [String],
        createdAt: Int,
        credentialExpiresAt: Int,
        expired: Bool,
        expiresSoon: Bool,
        revoked: Bool,
        organisationID: String,
        organisationName: String,
        canMutate: Bool
    ) {
        self.nodeID = nodeID
        self.technicalName = technicalName
        self.friendlyName = friendlyName
        self.wireGuardPublicKey = wireGuardPublicKey
        self.endpoint = endpoint
        self.allowedIPs = allowedIPs
        self.advertisedRoutes = advertisedRoutes
        self.approvedRoutes = approvedRoutes
        self.dnsName = dnsName
        self.tags = tags
        self.createdAt = createdAt
        self.credentialExpiresAt = credentialExpiresAt
        self.expired = expired
        self.expiresSoon = expiresSoon
        self.revoked = revoked
        self.organisationID = organisationID
        self.organisationName = organisationName
        self.canMutate = canMutate
    }

    private enum CodingKeys: String, CodingKey {
        case nodeID = "id"
        case technicalName = "name"
        case friendlyName = "display_name"
        case wireGuardPublicKey = "wg_public_key"
        case endpoint
        case allowedIPs = "allowed_ips"
        case advertisedRoutes = "advertised_routes"
        case approvedRoutes = "approved_routes"
        case dnsName = "dns_name"
        case tags
        case createdAt = "created_at"
        case credentialExpiresAt = "credential_expires_at"
        case expired
        case expiresSoon = "expires_soon"
        case revoked
        case organisationID = "organisation_id"
        case organisationName = "organisation_name"
        case canMutate = "can_mutate"
    }
}

public struct DesktopInventory: Codable, Equatable, Sendable {
    public var devices: [EndpointDevice]
    public var errors: [String]

    public init(devices: [EndpointDevice], errors: [String]) {
        self.devices = devices
        self.errors = errors
    }
}

public struct JoinKeyMaterial: Sendable {
    public var key: String
    public var expiresAt: Date
    public var coordinatorURL: String

    public init(key: String, expiresAt: Date, coordinatorURL: String) {
        self.key = key
        self.expiresAt = expiresAt
        self.coordinatorURL = coordinatorURL
    }

    public mutating func scrub() {
        key = String(repeating: "\0", count: key.count)
        key = ""
    }
}

public enum ConsoleClientError: LocalizedError, Sendable {
    case invalidURL
    case http(Int, String)
    case decoding
    case unauthorised

    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "The console URL is not valid."
        case .http(let code, let body):
            return "Console returned \(code): \(body)"
        case .decoding:
            return "Could not read the console response."
        case .unauthorised:
            return "Your session has expired. Sign in again."
        }
    }
}

/// Talks to the onshore Next.js console. Coordinator mutations go through the console, not offshore IdPs.
public struct ConsoleClient: Sendable {
    public var sessionToken: String
    public var baseURL: URL
    public var urlSession: URLSession

    public init(sessionToken: String, baseURL: URL, urlSession: URLSession = .shared) {
        self.sessionToken = sessionToken
        self.baseURL = baseURL
        self.urlSession = urlSession
    }

    public func fetchSession() async throws -> DesktopSession {
        let (data, response) = try await request(path: "/api/desktop/me", method: "GET", body: nil)
        guard let http = response as? HTTPURLResponse else { throw ConsoleClientError.decoding }
        if http.statusCode == 401 { throw ConsoleClientError.unauthorised }
        guard (200..<300).contains(http.statusCode) else {
            throw ConsoleClientError.http(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        let decoded = try JSONDecoder().decode(MeResponse.self, from: data)
        return DesktopSession(
            email: decoded.email,
            organisationID: decoded.organisationId,
            organisationName: decoded.organisationName,
            role: decoded.role,
            organisations: decoded.organisations,
            coordinatorURL: decoded.coordinatorUrl
        )
    }

    public func fetchDevices() async throws -> DesktopInventory {
        let (data, response) = try await request(path: "/api/desktop/devices", method: "GET", body: nil)
        try validate(response: response, data: data)
        guard let decoded = try? JSONDecoder().decode(DesktopInventory.self, from: data) else {
            throw ConsoleClientError.decoding
        }
        return decoded
    }

    public func mintJoinKey(
        organisationID: String? = nil,
        tags: [String] = [],
        expiresInSeconds: Int = 600
    ) async throws -> JoinKeyMaterial {
        let payload = try JSONSerialization.data(withJSONObject: [
            "tags": tags,
            "expiresInSeconds": expiresInSeconds,
            "singleUse": true
        ])
        let (data, response) = try await request(
            path: "/api/desktop/join-key",
            method: "POST",
            body: payload,
            organisationID: organisationID
        )
        guard let http = response as? HTTPURLResponse else { throw ConsoleClientError.decoding }
        if http.statusCode == 401 { throw ConsoleClientError.unauthorised }
        guard (200..<300).contains(http.statusCode) else {
            throw ConsoleClientError.http(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        let decoded = try JSONDecoder().decode(JoinKeyResponse.self, from: data)
        return JoinKeyMaterial(
            key: decoded.key,
            expiresAt: Date(timeIntervalSince1970: TimeInterval(decoded.expiresAt)),
            coordinatorURL: decoded.coordinatorUrl
        )
    }

    public func updateFriendlyName(
        nodeID: String,
        organisationID: String,
        friendlyName: String
    ) async throws {
        let body = try JSONSerialization.data(withJSONObject: [
            "operation": "rename",
            "friendlyName": friendlyName
        ])
        let (data, response) = try await request(
            path: "/api/desktop/devices/\(nodeID)",
            method: "PATCH",
            body: body,
            organisationID: organisationID
        )
        try validate(response: response, data: data)
    }

    public func approveRoutes(
        nodeID: String,
        organisationID: String,
        approvedRoutes: [String]
    ) async throws {
        let body = try JSONSerialization.data(withJSONObject: [
            "operation": "routes",
            "approvedRoutes": approvedRoutes
        ])
        let (data, response) = try await request(
            path: "/api/desktop/devices/\(nodeID)",
            method: "PATCH",
            body: body,
            organisationID: organisationID
        )
        try validate(response: response, data: data)
    }

    public func revokeDevice(nodeID: String, organisationID: String) async throws {
        let (data, response) = try await request(
            path: "/api/desktop/devices/\(nodeID)",
            method: "DELETE",
            body: nil,
            organisationID: organisationID
        )
        try validate(response: response, data: data)
    }

    /// App sign-out: revokes this desktop credential on the console.
    public func revokeCredential() async throws {
        let (data, response) = try await request(
            path: "/api/desktop/auth/token",
            method: "DELETE",
            body: nil
        )
        try validate(response: response, data: data)
    }

    private func request(
        path: String,
        method: String,
        body: Data?,
        organisationID: String? = nil
    ) async throws -> (Data, URLResponse) {
        let trimmed = path.hasPrefix("/") ? String(path.dropFirst()) : path
        let url = baseURL.appending(path: trimmed)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(sessionToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let organisationID, !organisationID.isEmpty {
            request.setValue(organisationID, forHTTPHeaderField: "X-BlakTail-Organisation")
        }
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return try await urlSession.data(for: request)
    }

    private func validate(response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else {
            throw ConsoleClientError.decoding
        }
        if http.statusCode == 401 { throw ConsoleClientError.unauthorised }
        guard (200..<300).contains(http.statusCode) else {
            throw ConsoleClientError.http(
                http.statusCode,
                String(data: data, encoding: .utf8) ?? ""
            )
        }
    }

    private struct MeResponse: Decodable {
        var email: String
        var organisationId: String
        var organisationName: String
        var role: String
        var organisations: [DesktopOrganisation]
        var coordinatorUrl: String?
    }

    private struct JoinKeyResponse: Decodable {
        var key: String
        var expiresAt: Int
        var coordinatorUrl: String
    }
}
