import BlakTailCore
import XCTest

final class AgentStatusParserTests: XCTestCase {
    func testParsesJoinedStatus() {
        let status = AgentStatus.parse(
            """
            joined
            node: 00000000-0000-0000-0000-000000000001
            address: 100.64.0.1/32
            coordinator: https://coord.example.org.au
            """
        )
        XCTAssertTrue(status.connected)
        XCTAssertEqual(status.address, "100.64.0.1/32")
        XCTAssertEqual(status.coordinator, "https://coord.example.org.au")
    }

    func testMissingJoinedMeansDisconnected() {
        XCTAssertFalse(AgentStatus.parse("error: not joined\n").connected)
    }
}

final class JoinKeySafetyTests: XCTestCase {
    func testUpArgumentsOmitJoinKey() throws {
        let joinKey = "bt_join_secret_value_do_not_leak"
        let args = AgentController.upArguments(
            coordinator: "https://coord.example.org.au",
            name: "mac-one"
        )
        try AgentController.assertNoJoinKeyInArguments(args, joinKey: joinKey)
        XCTAssertFalse(args.contains(joinKey))
        XCTAssertFalse(args.contains("--join-key"))
        XCTAssertFalse(args.contains(where: { $0.hasPrefix("BLAKTAIL_JOIN_KEY") }))
        // Server-assigned addressing: the app never passes a tailnet address.
        XCTAssertFalse(args.contains("--address"))
        XCTAssertTrue(args.contains("--coord"))
        XCTAssertTrue(args.contains("--exit-after-join"))
    }

    func testDetectsJoinKeyLeakInArguments() {
        let joinKey = "bt_join_secret_value_do_not_leak"
        XCTAssertThrowsError(
            try AgentController.assertNoJoinKeyInArguments(
                ["blaktaild", "up", "--join-key", joinKey],
                joinKey: joinKey
            )
        )
    }

    func testConnectPassesJoinKeyOnlyOnStdin() throws {
        let joinKey = "bt_join_secret_value_do_not_leak"
        let runner = RecordingRunner()
        let agentPath = makeTempExecutable()
        defer { try? FileManager.default.removeItem(atPath: agentPath) }

        let controller = AgentController(
            agentPath: agentPath,
            launchDaemonLabel: "com.blaktail.agent",
            launchDaemonPlist: "/Library/LaunchDaemons/com.blaktail.agent.plist",
            runner: runner
        )
        try controller.connect(
            joinKey: joinKey,
            coordinator: "https://coord.example.org.au",
            name: "mac-one"
        )

        let up = try XCTUnwrap(runner.calls.first)
        XCTAssertEqual(up.executable, agentPath)
        XCTAssertEqual(up.arguments.first, "up")
        XCTAssertFalse(up.arguments.contains(joinKey))
        XCTAssertEqual(up.stdin.flatMap { String(data: $0, encoding: .utf8) }, joinKey)
        XCTAssertTrue(up.privileged)
    }

    func testPauseRetainsEnrollmentInsteadOfCallingDown() throws {
        let runner = RecordingRunner()
        let agentPath = makeTempExecutable()
        defer { try? FileManager.default.removeItem(atPath: agentPath) }
        let controller = AgentController(
            agentPath: agentPath,
            launchDaemonLabel: "com.blaktail.agent",
            launchDaemonPlist: "/Library/LaunchDaemons/com.blaktail.agent.plist",
            runner: runner
        )

        try controller.pause()

        XCTAssertTrue(runner.calls.contains(where: { $0.arguments == ["pause"] }))
        XCTAssertFalse(runner.calls.contains(where: { $0.arguments == ["down"] }))
        XCTAssertTrue(
            runner.calls.contains(where: {
                $0.executable == "/bin/launchctl" &&
                    $0.arguments == ["bootout", "system/com.blaktail.agent"]
            })
        )
    }

    func testResumeBootstrapsSavedEnrollmentWithoutJoinKey() throws {
        let runner = RecordingRunner()
        let agentPath = makeTempExecutable()
        defer { try? FileManager.default.removeItem(atPath: agentPath) }
        let controller = AgentController(
            agentPath: agentPath,
            launchDaemonLabel: "com.blaktail.agent",
            launchDaemonPlist: "/Library/LaunchDaemons/com.blaktail.agent.plist",
            runner: runner
        )

        try controller.resume()

        XCTAssertTrue(
            runner.calls.contains(where: {
                $0.executable == "/bin/launchctl" &&
                    $0.arguments == [
                        "bootstrap",
                        "system",
                        "/Library/LaunchDaemons/com.blaktail.agent.plist"
                    ]
            })
        )
        XCTAssertFalse(runner.calls.contains(where: { $0.stdin != nil }))
    }

    func testPausedStatusRetainsNodeIdentity() throws {
        let agentPath = makeTempExecutable()
        defer { try? FileManager.default.removeItem(atPath: agentPath) }
        let controller = AgentController(
            agentPath: agentPath,
            launchDaemonLabel: "com.blaktail.agent",
            launchDaemonPlist: "/Library/LaunchDaemons/com.blaktail.agent.plist",
            runner: PausedStatusRunner()
        )

        let status = try controller.status()

        XCTAssertFalse(status.connected)
        XCTAssertEqual(status.nodeID, "00000000-0000-0000-0000-000000000001")
        XCTAssertEqual(status.address, "100.64.0.1/32")
    }
}

final class TaglineTests: XCTestCase {
    func testSharedProjectMission() {
        XCTAssertEqual(
            Tagline.text,
            "Built by Indigenous Australians for Indigenous Australian organisations. Data stays onshore, Indigenous Australian organisations stay in control, and the code stays public."
        )
    }
}

final class BrowserSignInTokenTests: XCTestCase {
    func testS256ChallengeMatchesConsole() {
        // Same vector as apps/console/scripts/desktop-auth.test.mjs.
        XCTAssertEqual(
            PKCERequest.challenge(for: "fake-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"),
            "UGabefOy04PGSwE8r2regzUpjOv3s3b-B6535dMR02k"
        )
    }

    func testRandomRequestIsUrlSafeAndFresh() throws {
        let first = try PKCERequest.random()
        let second = try PKCERequest.random()
        XCTAssertEqual(first.verifier.count, 43)
        XCTAssertEqual(first.state.count, 43)
        XCTAssertNotEqual(first.verifier, second.verifier)
        XCTAssertNotEqual(first.state, second.state)
        XCTAssertNil(first.verifier.rangeOfCharacter(from: CharacterSet(charactersIn: "+/=")))
    }

    func testStartURLCarriesChallengeNotVerifier() throws {
        let pkce = PKCERequest(verifier: "fake-verifier-0123456789-abcdefghijklmnopqrstuvwxyz", state: "fake-state-0123456789")
        let url = BrowserSignIn.startURL(consoleBaseURL: URL(string: "https://console.example.org.au")!, pkce: pkce)
        let items = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
        XCTAssertEqual(items.first(where: { $0.name == "code_challenge" })?.value, pkce.challenge)
        XCTAssertEqual(items.first(where: { $0.name == "code_challenge_method" })?.value, "S256")
        XCTAssertEqual(items.first(where: { $0.name == "redirect_uri" })?.value, "blaktail://auth/callback")
        XCTAssertFalse(url.absoluteString.contains(pkce.verifier))
    }

    func testReadsCodeWhenStateMatches() throws {
        let url = URL(string: "blaktail://auth/callback?code=btc_fake&state=fake-state-0123456789")!
        XCTAssertEqual(try BrowserSignIn.authorizationCode(from: url, expectedState: "fake-state-0123456789"), "btc_fake")
    }

    func testRejectsWrongStateOrLegacyToken() {
        let wrong = URL(string: "blaktail://auth/callback?code=btc_fake&state=other-state-0123456789")!
        XCTAssertThrowsError(try BrowserSignIn.authorizationCode(from: wrong, expectedState: "fake-state-0123456789")) {
            XCTAssertEqual($0 as? BrowserSignInError, .stateMismatch)
        }
        let legacy = URL(string: "blaktail://auth/callback#token=session-token")!
        XCTAssertThrowsError(try BrowserSignIn.authorizationCode(from: legacy, expectedState: "fake-state-0123456789"))
    }

    func testDeniedCallbackIsCancelled() {
        let url = URL(string: "blaktail://auth/callback?error=access_denied&state=fake-state-0123456789")!
        XCTAssertThrowsError(try BrowserSignIn.authorizationCode(from: url, expectedState: "fake-state-0123456789")) {
            XCTAssertEqual($0 as? BrowserSignInError, .cancelled)
        }
    }
}

final class DesktopEndpointTests: XCTestCase {
    func testDecodesMultiNetworkEndpointInventory() throws {
        let data = Data(
            """
            {
              "devices": [{
                "id": "node-one",
                "name": "technical-mac",
                "display_name": "Community office Mac",
                "wg_public_key": "public-key",
                "endpoint": "203.0.113.8:51820",
                "allowed_ips": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
                "advertised_routes": ["10.42.0.0/24"],
                "approved_routes": [],
                "dns_name": "technical-mac.example.blaktail.internal",
                "tags": ["office"],
                "created_at": 1700000000,
                "credential_expires_at": 2000000000,
                "expired": false,
                "expires_soon": true,
                "revoked": false,
                "organisation_id": "org-one",
                "organisation_name": "Community Services",
                "can_mutate": true
              }],
              "errors": []
            }
            """.utf8
        )

        let inventory = try JSONDecoder().decode(DesktopInventory.self, from: data)
        let device = try XCTUnwrap(inventory.devices.first)
        XCTAssertEqual(device.id, "org-one:node-one")
        XCTAssertEqual(device.displayName, "Community office Mac")
        XCTAssertEqual(device.credentialState, .expiresSoon)
        XCTAssertEqual(device.organisationName, "Community Services")
        XCTAssertTrue(device.canMutate)
    }

    func testPreferencesPersistSelectedNetwork() {
        let suiteName = "BlakTailTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let preferences = Preferences(
            consoleBaseURL: "https://console.example.org.au",
            coordinatorURL: "https://coord.example.org.au",
            deviceName: "field-mac",
            selectedOrganisationID: "org-ranger"
        )

        preferences.save(defaults: defaults)

        XCTAssertEqual(Preferences.load(defaults: defaults), preferences)
    }

    func testDesktopMutationScopesBearerToNetwork() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RecordingURLProtocol.self]
        let session = URLSession(configuration: configuration)
        RecordingURLProtocol.handler = { request in
            XCTAssertEqual(request.httpMethod, "PATCH")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer session-token")
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-BlakTail-Organisation"), "org-ranger")
            let body = try requestBodyData(request)
            let payload = try XCTUnwrap(
                JSONSerialization.jsonObject(with: body) as? [String: String]
            )
            XCTAssertEqual(payload["operation"], "rename")
            XCTAssertEqual(payload["friendlyName"], "Ranger MacBook")
            return (
                HTTPURLResponse(
                    url: try XCTUnwrap(request.url),
                    statusCode: 204,
                    httpVersion: nil,
                    headerFields: nil
                )!,
                Data()
            )
        }

        try await ConsoleClient(
            sessionToken: "session-token",
            baseURL: URL(string: "https://console.example.org.au")!,
            urlSession: session
        ).updateFriendlyName(
            nodeID: "node-one",
            organisationID: "org-ranger",
            friendlyName: "Ranger MacBook"
        )
    }
}

private final class RecordingRunner: ProcessRunner, @unchecked Sendable {
    struct Call {
        var executable: String
        var arguments: [String]
        var stdin: Data?
        var privileged: Bool
    }

    private(set) var calls: [Call] = []

    func run(executable: String, arguments: [String], stdin: Data?, privileged: Bool) throws -> ProcessResult {
        calls.append(Call(executable: executable, arguments: arguments, stdin: stdin, privileged: privileged))
        return ProcessResult(exitCode: 0, stdout: "ok\n", stderr: "")
    }
}

private final class RecordingURLProtocol: URLProtocol {
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

private func requestBodyData(_ request: URLRequest) throws -> Data {
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

private struct PausedStatusRunner: ProcessRunner {
    func run(executable: String, arguments: [String], stdin: Data?, privileged: Bool) throws -> ProcessResult {
        if arguments == ["status"] {
            return ProcessResult(
                exitCode: 0,
                stdout: """
                joined
                node: 00000000-0000-0000-0000-000000000001
                address: 100.64.0.1/32
                coordinator: https://coord.example.org.au
                """,
                stderr: ""
            )
        }
        return ProcessResult(exitCode: 1, stdout: "", stderr: "service not loaded")
    }
}

private func makeTempExecutable() -> String {
    let path = FileManager.default.temporaryDirectory
        .appendingPathComponent("blaktaild-fake-\(UUID().uuidString)")
        .path
    FileManager.default.createFile(
        atPath: path,
        contents: Data("#!/bin/sh\nexit 0\n".utf8),
        attributes: [.posixPermissions: 0o755]
    )
    return path
}
