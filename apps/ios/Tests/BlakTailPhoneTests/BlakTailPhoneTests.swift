import BlakTailCore
@testable import BlakTailPhone
import XCTest

final class BlakTailPhoneTests: XCTestCase {
    func testWidgetSnapshotRoundTrip() {
        let suite = "au.org.blaktail.ios.widget-test.\(UUID().uuidString)"
        let snapshot = PhoneWidgetSnapshot(
            label: "Connected",
            organisation: "Community services",
            address: "100.64.0.8/32",
            connected: true,
            enrolled: true
        )
        PhoneWidgetStore.save(snapshot, suite: suite)
        XCTAssertEqual(PhoneWidgetStore.load(suite: suite), snapshot)
    }

    func testSharedProjectMission() {
        XCTAssertEqual(
            Tagline.text,
            "Built by Indigenous Australians for Indigenous Australian organisations. Data stays onshore, Indigenous Australian organisations stay in control, and the code stays public."
        )
    }

    func testCallbackTokenFromFragment() throws {
        let url = URL(string: "blaktail://auth/callback#token=abc%20def")!
        XCTAssertEqual(try BrowserSignIn.token(from: url), "abc def")
    }

    @MainActor
    func testSearchMatchesFriendlyNameMagicDNSAndNetwork() {
        let model = PhoneModel(
            preferences: .defaults,
            keychain: KeychainStore(
                service: "au.org.blaktail.ios.test",
                account: UUID().uuidString
            )
        )
        model.devices = [
            EndpointDevice(
                nodeID: "node-one",
                technicalName: "community-office-imac",
                friendlyName: "Community office iMac",
                wireGuardPublicKey: "public-key",
                endpoint: nil,
                allowedIPs: ["100.64.0.1/32"],
                advertisedRoutes: [],
                approvedRoutes: [],
                dnsName: "community-office-imac.25fe1727.blaktail",
                tags: ["office"],
                createdAt: 1,
                credentialExpiresAt: 2,
                expired: false,
                expiresSoon: false,
                revoked: false,
                organisationID: "org-one",
                organisationName: "Community services",
                canMutate: true
            ),
            EndpointDevice(
                nodeID: "node-two",
                technicalName: "field-laptop",
                friendlyName: "Field laptop",
                wireGuardPublicKey: "public-key-2",
                endpoint: nil,
                allowedIPs: ["100.64.0.2/32"],
                advertisedRoutes: [],
                approvedRoutes: [],
                dnsName: "field-laptop.25fe1727.blaktail",
                tags: [],
                createdAt: 1,
                credentialExpiresAt: 2,
                expired: false,
                expiresSoon: false,
                revoked: false,
                organisationID: "org-two",
                organisationName: "Ranger services",
                canMutate: false
            )
        ]

        XCTAssertEqual(model.devices(in: .all, matching: "iMac").map(\.nodeID), ["node-one"])
        XCTAssertEqual(model.devices(in: .all, matching: "25fe1727").count, 2)
        XCTAssertEqual(model.devices(in: .organisation("org-two"), matching: "").map(\.nodeID), ["node-two"])
        XCTAssertEqual(model.deviceCount(in: "org-one"), 1)
    }

    @MainActor
    func testConsoleURLPolicy() {
        let model = PhoneModel(
            preferences: Preferences(
                consoleBaseURL: "https://console.example.org.au",
                coordinatorURL: "https://coord.example.org.au",
                deviceName: "iPhone"
            ),
            keychain: KeychainStore(
                service: "au.org.blaktail.ios.test",
                account: UUID().uuidString
            )
        )
        XCTAssertEqual(model.consoleBaseURL?.host, "console.example.org.au")

        model.preferences.consoleBaseURL = "http://evil.example"
        XCTAssertNil(model.consoleBaseURL)

        model.preferences.consoleBaseURL = "http://127.0.0.1:13000"
        XCTAssertEqual(model.consoleBaseURL?.host, "127.0.0.1")
    }

    func testPhoneKeychainServiceIsDistinctFromMac() {
        XCTAssertEqual(KeychainStore.phoneSession.service, "au.org.blaktail.ios")
        XCTAssertEqual(KeychainStore.session.service, "au.org.blaktail.desktop")
    }

    @MainActor
    func testConnectMintsJoinKeyRegistersAndStartsTunnelWithoutPersistingJoinKey() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [PhoneRecordingURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let joinKey = "btk_join_secret_value_do_not_leak"
        let keys = WireGuardKeypair.generate()
        let tunnel = RecordingPacketTunnelController()
        let enrollmentSecrets = MemorySecretStore()
        let sessionSecrets = MemorySecretStore("session-token")
        defer { PhoneRecordingURLProtocol.handler = nil }

        PhoneRecordingURLProtocol.handler = { request in
            let url = try XCTUnwrap(request.url)
            if url.path == "/api/desktop/join-key" {
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "X-BlakTail-Organisation"), "org-one")
                XCTAssertFalse((request.url?.absoluteString ?? "").contains(joinKey))
                return (
                    HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                    Data(
                        """
                        {"key":"\(joinKey)","expiresAt":2000000000,"coordinatorUrl":"https://coord.example.org.au"}
                        """.utf8
                    )
                )
            }
            if url.path == "/v1/nodes/register" {
                let body = try phoneRequestBody(request)
                let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
                XCTAssertEqual(payload["join_key"] as? String, joinKey)
                XCTAssertEqual(payload["wg_public_key"] as? String, keys.publicKey)
                XCTAssertEqual(payload["allowed_ips"] as? [String], [])
                XCTAssertFalse(url.absoluteString.contains(joinKey))
                return (
                    HTTPURLResponse(url: url, statusCode: 201, httpVersion: nil, headerFields: nil)!,
                    Data(
                        """
                        {
                          "id": "00000000-0000-0000-0000-000000000008",
                          "node_token": "btn_phone_token",
                          "assigned_ip": "100.64.0.8/32",
                          "assigned_ips": ["100.64.0.8/32"],
                          "dns_name": "field-iphone.25fe1727.blaktail",
                          "credential_expires_at": 2000000000
                        }
                        """.utf8
                    )
                )
            }
            if url.path == "/api/desktop/devices" {
                return (
                    HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                    Data(#"{"devices":[],"errors":[]}"#.utf8)
                )
            }
            XCTFail("unexpected request \(url.absoluteString)")
            throw URLError(.badURL)
        }

        let model = PhoneModel(
            preferences: Preferences(
                consoleBaseURL: "https://console.example.org.au",
                coordinatorURL: "https://coord.example.org.au",
                deviceName: "field-iphone",
                selectedOrganisationID: "org-one"
            ),
            keychain: sessionSecrets,
            enrollmentStore: EnrollmentStore(secrets: enrollmentSecrets),
            tunnel: tunnel,
            urlSession: session,
            generateKeys: { keys }
        )
        model.session = DesktopSession(
            email: "owner@example.org.au",
            organisationID: "org-one",
            organisationName: "Community services",
            role: "owner",
            organisations: [
                DesktopOrganisation(id: "org-one", name: "Community services", role: "owner")
            ],
            coordinatorURL: "https://coord.example.org.au"
        )

        await model.connect()

        XCTAssertEqual(model.connectionState, .connected)
        XCTAssertEqual(model.enrollment?.nodeID, "00000000-0000-0000-0000-000000000008")
        XCTAssertEqual(model.enrollment?.wireGuardPublicKey, keys.publicKey)
        XCTAssertEqual(model.enrollment?.wireGuardPrivateKey, keys.privateKey)
        XCTAssertEqual(tunnel.startCount, 1)
        let stored = try XCTUnwrap(enrollmentSecrets.load())
        XCTAssertFalse(stored.contains(joinKey))
        XCTAssertFalse(stored.contains("join_key"))
        XCTAssertTrue(stored.contains("btn_phone_token"))
    }

    @MainActor
    func testDisconnectPausesTunnelAndKeepsEnrollment() async throws {
        let store = EnrollmentStore(secrets: MemorySecretStore())
        let enrollment = NodeEnrollment(
            nodeID: "node-phone",
            nodeToken: "btn_token",
            coordinatorURL: "https://coord.example.org.au",
            organisationID: "org-one",
            organisationName: "Community services",
            deviceName: "field-iphone",
            assignedIP: "100.64.0.8/32",
            assignedIPs: ["100.64.0.8/32"],
            dnsName: "field-iphone.25fe1727.blaktail",
            credentialExpiresAt: 2000000000,
            wireGuardPrivateKey: "private",
            wireGuardPublicKey: "public"
        )
        try store.save(enrollment)
        let tunnel = RecordingPacketTunnelController()
        tunnel.running = true
        let model = PhoneModel(
            keychain: MemorySecretStore(),
            enrollmentStore: store,
            tunnel: tunnel
        )
        model.enrollment = enrollment
        model.connectionState = .connected

        await model.disconnect()

        XCTAssertEqual(model.connectionState, .disconnected)
        XCTAssertEqual(model.enrollment?.nodeID, "node-phone")
        XCTAssertEqual(tunnel.stopCount, 1)
        XCTAssertNotNil(try store.load())
    }
}

final class RecordingPacketTunnelController: PacketTunnelControlling, @unchecked Sendable {
    var startCount = 0
    var stopCount = 0
    var running = false

    func start() async throws {
        startCount += 1
        running = true
    }

    func stop() async throws {
        stopCount += 1
        running = false
    }

    func isRunning() async -> Bool { running }
}

private final class PhoneRecordingURLProtocol: URLProtocol {
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

private func phoneRequestBody(_ request: URLRequest) throws -> Data {
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
