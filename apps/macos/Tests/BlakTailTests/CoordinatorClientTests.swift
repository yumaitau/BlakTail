import XCTest
@testable import BlakTailCore

final class WireGuardKeypairTests: XCTestCase {
    func testGeneratedKeysAreStandardBase64ThirtyTwoBytes() throws {
        let keys = WireGuardKeypair.generate()
        let privateRaw = try WireGuardKeypair.rawKey(keys.privateKey)
        let publicRaw = try WireGuardKeypair.rawKey(keys.publicKey)
        XCTAssertEqual(privateRaw.count, 32)
        XCTAssertEqual(publicRaw.count, 32)
        XCTAssertEqual(try WireGuardKeypair.publicKey(fromPrivateKeyBase64: keys.privateKey), keys.publicKey)
        XCTAssertFalse(keys.privateKey.contains("-") || keys.privateKey.contains("_"))
    }
}

final class MagicDNSTests: XCTestCase {
    func testExtractsOrganisationDomain() {
        XCTAssertEqual(MagicDNS.domain(from: "community-office-imac.25fe1727.blaktail"), "25fe1727.blaktail")
        XCTAssertEqual(MagicDNS.hostLabel(from: "community-office-imac.25fe1727.blaktail"), "community-office-imac")
        XCTAssertNil(MagicDNS.domain(from: "node.example.com"))
        XCTAssertNil(MagicDNS.domain(from: "node.../etc.blaktail"))
    }
}

final class CoordinatorClientTests: XCTestCase {
    override func tearDown() {
        CoordinatorRecordingURLProtocol.handler = nil
        super.tearDown()
    }

    func testRegisterDecodesAssignedAddressesAndOmitsJoinKeyFromEnrollment() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CoordinatorRecordingURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let joinKey = "btk_join_secret_value_do_not_leak"
        CoordinatorRecordingURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/nodes/register")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
            let body = try coordinatorRequestBody(request)
            let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
            XCTAssertEqual(payload["join_key"] as? String, joinKey)
            XCTAssertEqual(payload["wg_public_key"] as? String, "public-key")
            XCTAssertEqual(payload["allowed_ips"] as? [String], [])
            XCTAssertEqual(payload["capabilities"] as? [String], ["wireguard", "magicdns"])
            XCTAssertEqual(payload["os"] as? String, "ios")
            let url = try XCTUnwrap(request.url)
            XCTAssertFalse(url.absoluteString.contains(joinKey))
            return (
                HTTPURLResponse(url: url, statusCode: 201, httpVersion: nil, headerFields: nil)!,
                Data(
                    """
                    {
                      "id": "00000000-0000-0000-0000-000000000001",
                      "org_id": "00000000-0000-0000-0000-000000000099",
                      "node_token": "btn_node_token",
                      "assigned_ip": "100.64.0.8/32",
                      "assigned_ips": ["100.64.0.8/32", "fd7a:115c:a1e0::8/128"],
                      "dns_name": "field-iphone.25fe1727.blaktail",
                      "credential_expires_at": 2000000000,
                      "relays": ["198.51.100.9:41641"],
                      "relay_token": "relay-token",
                      "relay_expires_at": 99
                    }
                    """.utf8
                )
            )
        }

        let client = try CoordinatorClient(
            coordinator: "https://coord.example.org.au",
            urlSession: session
        )
        let enrollment = try await client.register(
            joinKey: joinKey,
            name: "field-iphone",
            publicKey: "public-key",
            organisationID: "org-one",
            organisationName: "Community services"
        )

        XCTAssertEqual(enrollment.nodeID, "00000000-0000-0000-0000-000000000001")
        XCTAssertEqual(enrollment.nodeToken, "btn_node_token")
        XCTAssertEqual(enrollment.assignedIPs, ["100.64.0.8/32", "fd7a:115c:a1e0::8/128"])
        XCTAssertEqual(enrollment.dnsName, "field-iphone.25fe1727.blaktail")
        XCTAssertEqual(enrollment.organisationID, "org-one")
        XCTAssertTrue(enrollment.wireGuardPrivateKey.isEmpty)
        XCTAssertFalse(enrollment.containsJoinKey)
        let encoded = try JSONEncoder().encode(enrollment)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertFalse(json.contains(joinKey))
        XCTAssertFalse(json.contains("join_key"))
    }

    func testPeersRequestUsesNodeBearerAndIPv6() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CoordinatorRecordingURLProtocol.self]
        let session = URLSession(configuration: configuration)
        CoordinatorRecordingURLProtocol.handler = { request in
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer btn_node_token")
            XCTAssertEqual(request.url?.query, "ipv6=true")
            return (
                HTTPURLResponse(url: try XCTUnwrap(request.url), statusCode: 200, httpVersion: nil, headerFields: nil)!,
                Data(
                    """
                    {
                      "peers": [{
                        "id": "00000000-0000-0000-0000-000000000002",
                        "name": "office-imac",
                        "wg_public_key": "peer-public",
                        "endpoint": "203.0.113.8:51820",
                        "allowed_ips": ["100.64.0.1/32"],
                        "dns_name": "office-imac.25fe1727.blaktail",
                        "tags": ["office"],
                        "relay_endpoint": null
                      }],
                      "assigned_ips": ["100.64.0.8/32"],
                      "dns_name": "field-iphone.25fe1727.blaktail",
                      "credential_expires_at": 2000000000,
                      "relays": ["relay-a.example.org.au:3478"],
                      "relay_endpoints": [
                        {"endpoint": "relay-a.example.org.au:3478", "region": "ap-southeast-2", "wss": "wss://relay-a.example.org.au/v1/relay"},
                        {"endpoint": "relay-b.example.org.au:3478", "region": "australiaeast"}
                      ],
                      "relay_token": "ab",
                      "relay_expires_at": 99
                    }
                    """.utf8
                )
            )
        }

        let client = try CoordinatorClient(
            coordinator: "https://coord.example.org.au",
            urlSession: session
        )
        let snapshot = try await client.peers(enrollment: sampleEnrollment)
        XCTAssertEqual(snapshot.peers.first?.wireGuardPublicKey, "peer-public")
        XCTAssertEqual(snapshot.peers.first?.allowedIPs, ["100.64.0.1/32"])
        XCTAssertEqual(snapshot.dnsName, "field-iphone.25fe1727.blaktail")
        XCTAssertEqual(
            snapshot.relayEndpoints,
            [
                RelayEndpointInfo(
                    endpoint: "relay-a.example.org.au:3478",
                    region: "ap-southeast-2",
                    wss: "wss://relay-a.example.org.au/v1/relay"
                ),
                RelayEndpointInfo(endpoint: "relay-b.example.org.au:3478", region: "australiaeast")
            ]
        )
        XCTAssertEqual(snapshot.relayExpiresAt, 99)
    }

    func testRejectsPlaintextRemoteCoordinator() {
        XCTAssertThrowsError(try CoordinatorClient(coordinator: "http://coord.example.org.au")) { error in
            XCTAssertEqual(error as? CoordinatorClientError, .insecureURL)
        }
        XCTAssertNoThrow(try CoordinatorClient(coordinator: "http://127.0.0.1:8080"))
        XCTAssertNoThrow(try CoordinatorClient(coordinator: "https://coord.example.org.au"))
    }

    func testEnrollmentJSONNeverIncludesJoinKeyField() throws {
        let enrollment = sampleEnrollment
        let json = String(data: try JSONEncoder().encode(enrollment), encoding: .utf8) ?? ""
        XCTAssertFalse(json.contains("join_key"))
        XCTAssertFalse(json.contains("joinKey"))
        XCTAssertFalse(json.contains("btk_"))
    }
}

private let sampleEnrollment = NodeEnrollment(
    nodeID: "00000000-0000-0000-0000-000000000001",
    nodeToken: "btn_node_token",
    coordinatorURL: "https://coord.example.org.au",
    organisationID: "org-one",
    organisationName: "Community services",
    deviceName: "field-iphone",
    assignedIP: "100.64.0.8/32",
    assignedIPs: ["100.64.0.8/32"],
    dnsName: "field-iphone.25fe1727.blaktail",
    credentialExpiresAt: 2000000000,
    wireGuardPrivateKey: "private-key",
    wireGuardPublicKey: "public-key"
)

private final class CoordinatorRecordingURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        do {
            let handler = try XCTUnwrap(Self.handler)
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

private func coordinatorRequestBody(_ request: URLRequest) throws -> Data {
    if let body = request.httpBody {
        return body
    }
    let stream = try XCTUnwrap(request.httpBodyStream)
    stream.open()
    defer { stream.close() }
    var body = Data()
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while true {
        let count = stream.read(&buffer, maxLength: buffer.count)
        if count < 0 {
            throw stream.streamError ?? URLError(.cannotDecodeContentData)
        }
        if count == 0 {
            return body
        }
        body.append(contentsOf: buffer.prefix(count))
    }
}
