import BlakTailCore
import Foundation
import Observation

@MainActor
@Observable
public final class PhoneModel {
    public var preferences: Preferences
    public var session: DesktopSession?
    public var connectionState: ConnectionState = .disconnected
    /// Path the running tunnel measured (direct, Australian relay, HTTPS fallback).
    public var observedTransport: TunnelTransportStatus?
    public var enrollment: NodeEnrollment?
    public var devices: [EndpointDevice] = []
    public var inventoryErrors: [String] = []
    public var lastError: String?
    public var feedbackMessage: String?
    public var isBusy = false
    public var isLoadingDevices = false
    public var pendingDeviceID: String?
    public var lastRefreshedAt: Date?

    @ObservationIgnored public let keychain: any SecretStoring
    @ObservationIgnored public let enrollmentStore: EnrollmentStore
    @ObservationIgnored public let browserSignIn: BrowserSignIn
    @ObservationIgnored public let tunnel: any PacketTunnelControlling
    @ObservationIgnored public let urlSession: URLSession
    @ObservationIgnored public var generateKeys: @Sendable () -> WireGuardKeypair
    @ObservationIgnored var hasBootstrapped = false

    public init(
        preferences: Preferences = .load(),
        keychain: any SecretStoring = KeychainStore.phoneSession,
        enrollmentStore: EnrollmentStore? = nil,
        browserSignIn: BrowserSignIn? = nil,
        tunnel: (any PacketTunnelControlling)? = nil,
        urlSession: URLSession = .shared,
        generateKeys: @escaping @Sendable () -> WireGuardKeypair = { WireGuardKeypair.generate() }
    ) {
        self.preferences = preferences
        self.keychain = keychain
        self.enrollmentStore = enrollmentStore ?? EnrollmentStore()
        self.browserSignIn = browserSignIn ?? BrowserSignIn()
        self.tunnel = tunnel ?? PacketTunnelController.system
        self.urlSession = urlSession
        self.generateKeys = generateKeys
    }

    public var isSignedIn: Bool { session != nil }

    public var selectedOrganisation: DesktopOrganisation? {
        guard let session else { return nil }
        return session.organisations.first(where: { $0.id == preferences.selectedOrganisationID })
            ?? session.organisations.first
    }

    public var localDevice: EndpointDevice? {
        guard let nodeID = enrollment?.nodeID else { return nil }
        return devices.first(where: { $0.nodeID == nodeID })
    }

    public var connectionSymbol: String {
        switch connectionState {
        case .connected: return "iphone"
        case .connecting, .disconnecting: return "iphone.radiowaves.left.and.right"
        case .disconnected: return "iphone.slash"
        }
    }

    public var activeDeviceCount: Int {
        devices.filter { !$0.expired && !$0.revoked }.count
    }

    public var consoleBaseURL: URL? {
        guard let url = URL(string: preferences.consoleBaseURL),
              url.scheme == "https" || url.host == "127.0.0.1" || url.host == "localhost"
        else {
            return nil
        }
        return url
    }

    public func bootstrap() {
        guard !hasBootstrapped else { return }
        hasBootstrapped = true
        Task {
            loadEnrollment()
            await restoreSessionIfPossible()
            await refreshTunnelStatus()
        }
    }

    public func savePreferences() {
        preferences.save()
    }

    public func selectOrganisation(_ organisationID: String) {
        guard session?.organisations.contains(where: { $0.id == organisationID }) == true else {
            return
        }
        preferences.selectedOrganisationID = organisationID
        preferences.save()
    }

    public func devices(in scope: NetworkScope, matching searchText: String) -> [EndpointDevice] {
        let scoped: [EndpointDevice]
        switch scope {
        case .all:
            scoped = devices
        case .organisation(let organisationID):
            scoped = devices.filter { $0.organisationID == organisationID }
        }
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return scoped }
        return scoped.filter { device in
            [
                device.displayName,
                device.technicalName,
                device.dnsName,
                device.organisationName,
                device.allowedIPs.joined(separator: " "),
                device.tags.joined(separator: " ")
            ].contains { $0.localizedCaseInsensitiveContains(query) }
        }
    }

    public func deviceCount(in organisationID: String) -> Int {
        devices.filter { $0.organisationID == organisationID }.count
    }
}

public enum NetworkScope: Hashable, Sendable {
    case all
    case organisation(String)
}
