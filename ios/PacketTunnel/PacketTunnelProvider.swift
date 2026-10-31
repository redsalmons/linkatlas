import NetworkExtension

/// Routes all traffic into the tunnel; the C core forwards it unchanged and
/// hands every packet to the C++ analyzer.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var tunnel: OpaquePointer?
    private var analyzer: UnsafeMutableRawPointer?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let v4 = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        v4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = v4
        let v6 = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
        v6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = v6
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                completionHandler(error)
                return
            }
            let analyzer = wd_analyzer_create()
            let ctx = Unmanaged.passUnretained(self).toOpaque()
            guard let tunnel = wd_tunnel_create({ ctx, packet, len in
                guard let ctx, let packet, len > 0 else { return }
                let me = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue()
                let proto = packet[0] >> 4 == 6 ? AF_INET6 : AF_INET
                me.packetFlow.writePackets([Data(bytes: packet, count: len)],
                                           withProtocols: [NSNumber(value: proto)])
            }, nil, ctx, wd_analyzer_on_packet, analyzer) else {
                wd_analyzer_destroy(analyzer)
                completionHandler(NSError(domain: "MobileWatchdog", code: 1,
                                          userInfo: [NSLocalizedDescriptionKey: "tunnel init failed"]))
                return
            }
            self.analyzer = analyzer
            self.tunnel = tunnel
            completionHandler(nil)
            self.readPackets()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
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
}
