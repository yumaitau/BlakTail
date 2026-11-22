#if canImport(AppKit)
import AppKit
#endif
#if canImport(UIKit)
import UIKit
#endif
import AuthenticationServices
import CryptoKit
import Foundation
import Security

public enum BrowserSignInError: LocalizedError, Sendable, Equatable {
    case cancelled
    case missingToken
    case invalidCallback
    case stateMismatch
    case exchangeFailed(String)

    public var errorDescription: String? {
        switch self {
        case .cancelled:
            return "Sign-in was cancelled."
        case .missingToken:
            return "The console did not return a sign-in code."
        case .invalidCallback:
            return "The sign-in callback URL was not recognised."
        case .stateMismatch:
            return "The sign-in response did not match this request. Try again."
        case .exchangeFailed(let detail):
            return "The console refused the sign-in: \(detail)"
        }
    }
}

/// PKCE (RFC 7636, S256) values for one sign-in attempt.
public struct PKCERequest: Sendable, Equatable {
    public var verifier: String
    public var challenge: String
    public var state: String

    public init(verifier: String, state: String) {
        self.verifier = verifier
        self.challenge = Self.challenge(for: verifier)
        self.state = state
    }

    /// 32 random bytes each from SecRandomCopyBytes, base64url-encoded (43 characters).
    public static func random() throws -> PKCERequest {
        PKCERequest(verifier: try randomToken(), state: try randomToken())
    }

    public static func challenge(for verifier: String) -> String {
        base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
    }

    static func randomToken() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw BrowserSignInError.invalidCallback }
        return base64URL(Data(bytes))
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// Opens the onshore console in ASWebAuthenticationSession, receives a one-use
/// code on `blaktail://auth/callback`, and exchanges it (with the PKCE
/// verifier) for a desktop credential. The browser session never reaches the app.
@MainActor
public final class BrowserSignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    public nonisolated static let callbackScheme = "blaktail"
    public nonisolated static let redirectURI = "blaktail://auth/callback"

    private var activeSession: ASWebAuthenticationSession?

    public override init() {
        super.init()
    }

    public func signIn(consoleBaseURL: URL, urlSession: URLSession = .shared) async throws -> String {
        let pkce = try PKCERequest.random()
        let start = Self.startURL(consoleBaseURL: consoleBaseURL, pkce: pkce)
        let callbackURL: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: start,
                callbackURLScheme: Self.callbackScheme
            ) { [weak self] callbackURL, error in
                self?.activeSession = nil
                if let error {
                    if let authError = error as? ASWebAuthenticationSessionError,
                       authError.code == .canceledLogin {
                        continuation.resume(throwing: BrowserSignInError.cancelled)
                    } else {
                        continuation.resume(throwing: error)
                    }
                    return
                }
                guard let callbackURL else {
                    continuation.resume(throwing: BrowserSignInError.invalidCallback)
                    return
                }
                continuation.resume(returning: callbackURL)
            }
            session.prefersEphemeralWebBrowserSession = false
            session.presentationContextProvider = self
            self.activeSession = session
            if !session.start() {
                self.activeSession = nil
                continuation.resume(throwing: BrowserSignInError.invalidCallback)
            }
        }
        let code = try Self.authorizationCode(from: callbackURL, expectedState: pkce.state)
        return try await Self.exchange(
            code: code,
            verifier: pkce.verifier,
            consoleBaseURL: consoleBaseURL,
            urlSession: urlSession
        )
    }

    public nonisolated static func startURL(consoleBaseURL: URL, pkce: PKCERequest) -> URL {
        var components = URLComponents(
            url: consoleBaseURL.appending(path: "desktop/auth"),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = [
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "state", value: pkce.state),
            URLQueryItem(name: "code_challenge", value: pkce.challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256")
        ]
        return components.url!
    }

    /// Reads `code` from `blaktail://auth/callback?code=…&state=…` after checking `state`.
    public nonisolated static func authorizationCode(from callbackURL: URL, expectedState: String) throws -> String {
        guard callbackURL.scheme == callbackScheme,
              callbackURL.host == "auth",
              callbackURL.path == "/callback",
              let items = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems
        else {
            throw BrowserSignInError.invalidCallback
        }
        func value(_ name: String) -> String? { items.first(where: { $0.name == name })?.value }
        guard let state = value("state"), !state.isEmpty, state == expectedState else {
            throw BrowserSignInError.stateMismatch
        }
        if value("error") != nil {
            throw BrowserSignInError.cancelled
        }
        guard let code = value("code"), !code.isEmpty else {
            throw BrowserSignInError.missingToken
        }
        return code
    }

    /// `POST /api/desktop/auth/token` with the code and verifier; returns the `btd_` credential.
    public nonisolated static func exchange(
        code: String,
        verifier: String,
        consoleBaseURL: URL,
        urlSession: URLSession = .shared
    ) async throws -> String {
        var request = URLRequest(url: consoleBaseURL.appending(path: "api/desktop/auth/token"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirectURI
        ])
        let (data, response) = try await urlSession.data(for: request)
        let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let detail = body?["error_description"] as? String ?? body?["error"] as? String ?? "unknown error"
            throw BrowserSignInError.exchangeFailed(detail)
        }
        guard let token = body?["token"] as? String, !token.isEmpty else {
            throw BrowserSignInError.missingToken
        }
        return token
    }

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if canImport(AppKit) && !targetEnvironment(macCatalyst)
        NSApplication.shared.windows.first ?? ASPresentationAnchor()
        #elseif canImport(UIKit)
        let windows = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
        return windows.first(where: \.isKeyWindow) ?? windows.first ?? ASPresentationAnchor()
        #else
        ASPresentationAnchor()
        #endif
    }
}
