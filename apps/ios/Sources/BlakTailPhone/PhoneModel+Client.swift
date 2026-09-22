import BlakTailCore

extension PhoneModel {
    public func connect() async {
        defer { publishWidget() }
        if enrollment != nil {
            isBusy = true
            connectionState = .connecting
            lastError = nil
            feedbackMessage = nil
            defer { isBusy = false }
            do {
                try await tunnel.start()
                connectionState = .connected
                feedbackMessage = "This iPhone resumed its saved BlakTail enrolment."
            } catch {
                connectionState = .disconnected
                lastError = error.localizedDescription
            }
            return
        }

        guard let token = try? keychain.load(), !token.isEmpty else {
            lastError = "Sign in before connecting."
            return
        }
        guard let base = consoleBaseURL else {
            lastError = "Set a valid onshore console URL first."
            return
        }
        guard let organisation = selectedOrganisation else {
            lastError = "Choose a network for this iPhone."
            return
        }
        guard organisation.canMutate else {
            lastError = "An owner or admin must enrol this iPhone in \(organisation.name)."
            return
        }

        isBusy = true
        connectionState = .connecting
        lastError = nil
        feedbackMessage = nil
        defer { isBusy = false }

        var material: JoinKeyMaterial?
        do {
            let client = ConsoleClient(
                sessionToken: token,
                baseURL: base,
                urlSession: urlSession
            )
            material = try await client.mintJoinKey(organisationID: organisation.id)
            var join = material!
            defer {
                join.scrub()
                material?.scrub()
            }
            let coordinator = join.coordinatorURL.isEmpty
                ? preferences.coordinatorURL
                : join.coordinatorURL
            preferences.coordinatorURL = coordinator
            preferences.save()

            let keys = generateKeys()
            var enrollment = try await CoordinatorClient(
                coordinator: coordinator,
                urlSession: urlSession
            ).register(
                joinKey: join.key,
                name: preferences.deviceName,
                publicKey: keys.publicKey,
                organisationID: organisation.id,
                organisationName: organisation.name
            )
            enrollment.wireGuardPrivateKey = keys.privateKey
            try enrollmentStore.save(enrollment)
            self.enrollment = enrollment
            try await tunnel.start()
            connectionState = .connected
            feedbackMessage = "This iPhone is connected to \(organisation.name)."
            await refreshDevices()
        } catch {
            material?.scrub()
            connectionState = .disconnected
            lastError = error.localizedDescription
        }
    }

    public func disconnect() async {
        defer { publishWidget() }
        isBusy = true
        connectionState = .disconnecting
        lastError = nil
        feedbackMessage = nil
        defer { isBusy = false }
        do {
            try await tunnel.stop()
            connectionState = .disconnected
            feedbackMessage = "This iPhone is disconnected."
        } catch {
            lastError = error.localizedDescription
            connectionState = (await tunnel.isRunning()) ? .connected : .disconnected
        }
    }

    public func leaveNetwork() async {
        defer { publishWidget() }
        isBusy = true
        lastError = nil
        feedbackMessage = nil
        defer { isBusy = false }
        let current = enrollment
        do {
            try? await tunnel.stop()
            if let current {
                try? await CoordinatorClient(
                    coordinator: current.coordinatorURL,
                    urlSession: urlSession
                ).revoke(enrollment: current)
            }
            try enrollmentStore.delete()
            enrollment = nil
            connectionState = .disconnected
            feedbackMessage = "This iPhone left the BlakTail network."
            await refreshDevices()
        } catch {
            lastError = error.localizedDescription
        }
    }

    public func loadEnrollment() {
        enrollment = try? enrollmentStore.load()
    }

    public func refreshTunnelStatus() async {
        if enrollment == nil {
            if connectionState == .connected {
                connectionState = .disconnected
            }
            publishWidget()
            return
        }
        if await tunnel.isRunning() {
            connectionState = .connected
        } else if connectionState == .connected {
            connectionState = .disconnected
        }
        publishWidget()
    }

    func publishWidget() {
        PhoneWidgetStore.save(
            PhoneWidgetSnapshot(
                label: enrollment == nil ? "Join in the app" : connectionState.label,
                organisation: enrollment?.organisationName ?? selectedOrganisation?.name ?? "",
                address: enrollment?.assignedIP ?? "",
                connected: connectionState == .connected,
                enrolled: enrollment != nil
            )
        )
    }
}
