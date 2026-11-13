import NetworkExtension
import os

/// Routes all traffic into the tunnel; the C core forwards it unchanged and
/// samples App packets and both byte streams for asynchronous analysis.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let log = Logger(subsystem: "com.redsalmons.linkatlas.tunnel", category: "forwarding")
    private var tunnel: OpaquePointer?
    private var analyzer: UnsafeMutableRawPointer?
    private var dnsRefreshTask: Task<Void, Never>?
    private var currentDNSServers: [String] = []

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        Self.log.notice("Starting packet tunnel")
        // A default-route tunnel also needs a default DNS resolver. Without it,
        // name resolution can fail before any application traffic reaches us.
        // Prefer the underlying network's own resolvers so resolution follows
        // whatever network the phone is on; public resolvers stay as fallback
        // because a hardcoded list can be unreachable on some networks.
        currentDNSServers = underlyingDNSServers() + ["223.5.5.5", "1.1.1.1"]
        let settings = networkSettings(dnsServers: currentDNSServers)

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                Self.log.error("Network settings failed: \(error.localizedDescription, privacy: .public)")
                completionHandler(error)
                return
            }
            guard let analyzer = wd_analyzer_create() else {
                completionHandler(NSError(domain: "LinkAtlas", code: 2,
                                          userInfo: [NSLocalizedDescriptionKey: "analyzer init failed"]))
                return
            }
            let ctx = Unmanaged.passUnretained(self).toOpaque()
            // Let iOS route the provider's relay sockets over the underlying
            // network; do not pin them to a guessed Wi-Fi/cellular interface.
            guard let tunnel = wd_tunnel_create({ ctx, packet, len in
                guard let ctx, let packet, len > 0 else { return }
                let me = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue()
                let proto = packet[0] >> 4 == 6 ? AF_INET6 : AF_INET
                me.packetFlow.writePackets([Data(bytes: packet, count: len)],
                                           withProtocols: [NSNumber(value: proto)])
            }, nil, ctx, wd_analyzer_on_event, analyzer) else {
                wd_analyzer_destroy(analyzer)
                completionHandler(NSError(domain: "LinkAtlas", code: 1,
                                          userInfo: [NSLocalizedDescriptionKey: "tunnel init failed"]))
                return
            }
            self.analyzer = analyzer
            self.tunnel = tunnel
            Self.log.notice("Forwarding core ready; starting packet reads")
            completionHandler(nil)
            self.readPackets()
            self.startDNSRefresh()
        }
    }

    /// Tunnel network settings are re-appliable while running, so a mid-session
    /// network switch (Wi-Fi <-> cellular) can swap in the new underlying DNS.
    private func networkSettings(dnsServers: [String]) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let v4 = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        v4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = v4
        let v6 = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
        v6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = v6
        settings.mtu = 1500
        settings.dnsSettings = NEDNSSettings(servers: dnsServers)
        settings.dnsSettings?.matchDomains = [""]
        return settings
    }

    private func startDNSRefresh() {
        dnsRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                self?.refreshDNSIfNeeded()
            }
        }
    }

    private func refreshDNSIfNeeded() {
        let fresh = underlyingDNSServers() + ["223.5.5.5", "1.1.1.1"]
        guard fresh != currentDNSServers else { return }
        currentDNSServers = fresh
        Self.log.notice("Underlying DNS changed; updating tunnel settings")
        setTunnelNetworkSettings(networkSettings(dnsServers: fresh)) { error in
            if let error {
                Self.log.error("DNS settings update failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// DNS servers configured on the underlying (non-tunnel) network, read via
    /// the C core's per-interface resolver lookup so resolution follows
    /// whatever network the phone is on. Returns [] when unavailable.
    private func underlyingDNSServers() -> [String] {
        var buffer = [CChar](repeating: 0, count: 256)
        let count = buffer.withUnsafeMutableBufferPointer {
            wd_dns_servers($0.baseAddress, $0.count)
        }
        guard count > 0 else { return [] }
        return String(cString: buffer).split(separator: ",").map(String.init)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        dnsRefreshTask?.cancel()
        dnsRefreshTask = nil
        if let tunnel { wd_tunnel_destroy(tunnel) }
        if let analyzer { wd_analyzer_destroy(analyzer) }
        tunnel = nil
        analyzer = nil
        completionHandler()
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let tunnel = self.tunnel else { return }
            for packet in packets {
                packet.withUnsafeBytes { raw in
                    guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
                    wd_tunnel_input(tunnel, base, raw.count)
                }
            }
            self.readPackets()
        }
    }

    /// UI query: active flows whose original destination is public unicast.
    /// Copies display fields only; Geo lookup remains in the app.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if messageData == Data([4]) {
            if let analyzer { wd_analyzer_reset(analyzer) }
            completionHandler?(Data([1]))
            return
        }
        if messageData == Data([3]) {
            completionHandler?(websiteVisits())
            return
        }
        guard messageData == Data([2]) else { completionHandler?(nil); return }
        var summaries = [wd_flow_summary](repeating: wd_flow_summary(), count: 256)
        var destinations = [[String: String]]()
        if let analyzer {
            let count = wd_analyzer_snapshot(analyzer, &summaries, summaries.count)
            // A resolver is infrastructure, not a visited site: its "domain" would be
            // whatever the client asked for, which the analyzer never records.
            for summary in summaries.prefix(count) where summary.closed == 0 && summary.protocol.0.rawValue != UInt32(WD_PROTOCOL_DNS.rawValue) {
                var ip = summary.flow.dst
                let isPublic = summary.flow.ipver == 4 ? publicIPv4(&ip) : publicIPv6(&ip)
                guard isPublic else { continue }
                var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                let family = summary.flow.ipver == 6 ? AF_INET6 : AF_INET
                _ = withUnsafeBytes(of: &ip) { bytes in
                    inet_ntop(family, bytes.baseAddress, &text, socklen_t(text.count))
                }
                let sni = displayString(summary.tls_sni)
                let host = displayString(summary.http_host)
                let name = sni.isEmpty ? host : sni
                if isAppInfrastructure(name) { continue }
                destinations.append(["ip": String(cString: text), "domain": name])
            }
        }
        let response = try? JSONEncoder().encode(destinations)
        completionHandler?(response)
    }

    private struct WebsiteVisit: Encodable {
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

    private func websiteVisits() -> Data? {
        guard let analyzer else { return try? JSONEncoder().encode([WebsiteVisit]()) }
        var count = wd_analyzer_destinations(analyzer, nil, 0)
        var records: [wd_destination_summary]
        repeat {
            records = [wd_destination_summary](repeating: wd_destination_summary(), count: count + 32)
            count = wd_analyzer_destinations(analyzer, &records, records.count)
        } while count > records.count
        // Learn the tile host's addresses first: a later flow to the same host may
        // arrive without SNI and would otherwise surface as a bare IP.
        let infrastructure = Set(records.prefix(count)
            .filter { isAppInfrastructure(displayString($0.domain)) }
            .map { "\($0.ipver):" + displayIP($0) })
        let visits = records.prefix(count).compactMap { record -> WebsiteVisit? in
            if record.protocol == 3 { return nil }  // DNS resolver, not a destination
            // The map download is the app's own infrastructure, not a visited site.
            if isAppInfrastructure(displayString(record.domain)) { return nil }
            if infrastructure.contains("\(record.ipver):" + displayIP(record)) { return nil }
            var ip = record.dst
            guard record.ipver == 4 ? publicIPv4(&ip) : publicIPv6(&ip) else { return nil }
            var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            _ = withUnsafeBytes(of: &ip) {
                inet_ntop(record.ipver == 6 ? AF_INET6 : AF_INET, $0.baseAddress, &text, socklen_t(text.count))
            }
            return WebsiteVisit(ip: String(cString: text), domain: displayString(record.domain),
                                tcpConnections: record.tcp_connections, udpFlows: record.udp_flows,
                                bytesOut: record.bytes.0, bytesIn: record.bytes.1,
                                protocol: record.protocol, fingerprint: fingerprintText(record),
                                domainSource: record.domain_source)
        }
        return try? JSONEncoder().encode(visits)
    }

    private func displayIP(_ record: wd_destination_summary) -> String {
        var address = record.dst
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        _ = withUnsafeBytes(of: &address) {
            inet_ntop(record.ipver == 6 ? AF_INET6 : AF_INET, $0.baseAddress, &text, socklen_t(text.count))
        }
        return String(cString: text)
    }

    /// The app's own tile download must never show up as a visited service.
    private func isAppInfrastructure(_ domain: String) -> Bool {
        let name = domain.lowercased()
        return name == "openfreemap.org" || name.hasSuffix(".openfreemap.org")
    }

    private func fingerprintText(_ record: wd_destination_summary) -> String {
        guard record.has_fingerprint != 0 else { return "" }
        let options = withUnsafeBytes(of: record.app_tcp_options) { bytes in
            bytes.prefix(Int(record.app_tcp_options_len)).prefix(12)
                .map { String(format: "%02x", $0) }.joined()
        }
        return options.isEmpty ? NSLocalizedString("无选项", comment: "empty TCP options") : options
    }

    private func displayString<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { bytes in
            let prefix = bytes.prefix { $0 != 0 }
            return String(decoding: prefix, as: UTF8.self)
        }
    }

    private func publicIPv4(_ ip: inout (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                                          UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)) -> Bool {
        let a = ip.0, b = ip.1
        return !(a == 0 || a == 10 || a == 127 || a >= 224 ||
                 (a == 100 && b >= 64 && b <= 127) ||
                 (a == 169 && b == 254) ||
                 (a == 172 && b >= 16 && b <= 31) ||
                 (a == 192 && b == 168) ||
                 (a == 192 && b == 0) ||
                 (a == 198 && (b == 18 || b == 19 || b == 51)) ||
                 (a == 203 && b == 0))
    }

    private func publicIPv6(_ ip: inout (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                                          UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)) -> Bool {
        var bytes = [UInt8]()
        withUnsafeBytes(of: &ip) { bytes = Array($0) }
        let allZero = bytes.allSatisfy { $0 == 0 }
        let loopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes[15] == 1
        return !allZero && !loopback &&
            (bytes[0] & 0xfe) != 0xfc &&
            !(bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) &&
            bytes[0] != 0xff &&
            !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
    }
}
