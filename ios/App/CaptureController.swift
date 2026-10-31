import NetworkExtension

/// Installs (first launch shows the system VPN prompt) and starts the packet tunnel.
@MainActor
final class CaptureController: ObservableObject {
    @Published private(set) var lastError: String?

    func start() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = managers.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.redsalmons.mobilewatchdog.tunnel"
            proto.serverAddress = "Local"
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Mobile Watchdog"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                try manager.connection.startVPNTunnel()
            }
        } catch {
            lastError = error.localizedDescription
        }
    }
}
