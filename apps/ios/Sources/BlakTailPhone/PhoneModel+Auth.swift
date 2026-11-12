import BlakTailCore

extension PhoneModel {
    public func signIn() async {
        isBusy = true
        lastError = nil
        feedbackMessage = nil
        defer { isBusy = false }
        do {
            guard let base = consoleBaseURL else {
                lastError = "Set a valid onshore console URL first."
                return
            }
            let token = try await browserSignIn.signIn(consoleBaseURL: base, urlSession: urlSession)
            try keychain.save(token)
            let desktop = try await ConsoleClient(
                sessionToken: token,
                baseURL: base,
                urlSession: urlSession
            ).fetchSession()
            applySession(desktop)
            await refreshDevices()
        } catch let error as BrowserSignInError where error == .cancelled {
            return
        } catch {
            lastError = error.localizedDescription
            session = nil
            devices = []
        }
    }

    public func signOut() {
        if let token = try? keychain.load(), !token.isEmpty, let base = consoleBaseURL {
            let client = ConsoleClient(sessionToken: token, baseURL: base, urlSession: urlSession)
            Task { try? await client.revokeCredential() }
        }
        try? keychain.delete()
        session = nil
        devices = []
        inventoryErrors = []
        lastError = nil
        feedbackMessage = nil
    }

    public func applySession(_ desktop: DesktopSession) {
        session = desktop
        if !desktop.organisations.contains(where: { $0.id == preferences.selectedOrganisationID }) {
            preferences.selectedOrganisationID = desktop.organisationID
        }
        if let coordinator = desktop.coordinatorURL, !coordinator.isEmpty {
            preferences.coordinatorURL = coordinator
        }
        preferences.save()
    }

    public func restoreSessionIfPossible() async {
        guard let token = try? keychain.load(), !token.isEmpty, let base = consoleBaseURL else {
            return
        }
        do {
            let desktop = try await ConsoleClient(
                sessionToken: token,
                baseURL: base,
                urlSession: urlSession
            ).fetchSession()
            applySession(desktop)
            await refreshDevices()
        } catch ConsoleClientError.unauthorised {
            try? keychain.delete()
            session = nil
            devices = []
        } catch {
            lastError = "Could not restore your account: \(error.localizedDescription)"
        }
    }
}
