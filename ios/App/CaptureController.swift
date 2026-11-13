import NetworkExtension

struct DestinationObservation: Decodable {
    let ip: String
    let domain: String
}

struct WebsiteVisit: Decodable, Equatable {
    let ip: String
    let domain: String
    let tcpConnections: UInt64
    let udpFlows: UInt64
    let bytesOut: UInt64
    let bytesIn: UInt64
    let `protocol`: UInt8
    let fingerprint: String
    let domainSource: UInt8
}

/// Installs (first launch shows the system VPN prompt) and starts the packet tunnel.
@MainActor
final class CaptureController: ObservableObject {
    @Published private(set) var lastError: String?
    /// Bumped on every successful explicit reset; consumers poll it to tell a
    /// user-requested clear from a transient empty snapshot.
    private(set) var resetGeneration = 0
    private var manager: NETunnelProviderManager?

    func start() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = managers.first ?? NETunnelProviderManager()
            self.manager = manager
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.redsalmons.linkatlas.tunnel"
            proto.serverAddress = "Local"
            manager.protocolConfiguration = proto
            manager.localizedDescription = NSLocalizedString("连线图志", comment: "VPN configuration name")
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                try manager.connection.startVPNTunnel()
            }
        } catch {
            lastError = error.localizedDescription
            NSLog("CaptureController.start failed: %@", error.localizedDescription)
        }
    }

    /// Returns active public destination addresses reported by the packet tunnel.
    /// The packet extension owns the analyzer; this is a UI-facing query only.
    func externalDestinations() async -> [DestinationObservation] {
        guard let session = manager?.connection as? NETunnelProviderSession else { return [] }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(Data([2])) { response in
                    guard let response,
                          let values = try? JSONDecoder().decode([DestinationObservation].self, from: response) else {
                        continuation.resume(returning: [])
                        return
                    }
                    continuation.resume(returning: values)
                }
            } catch {
                continuation.resume(returning: [])
            }
        }
    }

    /// Clears every record of the current session; the tunnel keeps forwarding.
    @discardableResult
    func reset() async -> Bool {
        guard let session = manager?.connection as? NETunnelProviderSession else { return false }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(Data([4])) { _ in
                    Task { @MainActor in self.resetGeneration += 1 }
                    continuation.resume(returning: true)
                }
            } catch {
                continuation.resume(returning: false)
            }
        }
    }

    func websiteVisits() async -> [WebsiteVisit] {
        guard let session = manager?.connection as? NETunnelProviderSession else { return [] }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(Data([3])) { response in
                    let values = response.flatMap { try? JSONDecoder().decode([WebsiteVisit].self, from: $0) }
                    continuation.resume(returning: values ?? [])
                }
            } catch {
                continuation.resume(returning: [])
            }
        }
    }
}
