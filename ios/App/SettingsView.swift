import SwiftUI

struct WebsiteStat: Identifiable, Equatable, Hashable {
    let id: String
    let domain: String
    let ips: [String]
    let tcp: UInt64
    let udp: UInt64
    let bytesOut: UInt64
    let bytesIn: UInt64
    var title: String { domain.isEmpty ? (ips.first ?? "") : domain }
    var bytes: UInt64 { bytesOut + bytesIn }

    /// Generates a stable request_id for lookup idempotency.
    func makeLookupRequestId() -> String { UUID().uuidString }
}

@MainActor
final class WebsiteStatsModel: ObservableObject {
    @Published private(set) var websites: [WebsiteStat] = []
    @Published private(set) var visits: [WebsiteVisit] = []
    @Published private(set) var whitelist: ServiceWhitelist = .stored

    var shownWebsites: [WebsiteStat] { websites.filter { !whitelist.matches($0) } }
    var hiddenWebsites: [WebsiteStat] { websites.filter { whitelist.matches($0) } }

    func refreshWhitelist() async {
        guard let wl = await LookupServiceClient.shared?.fetchWhitelist() else { return }
        ServiceWhitelist.stored = wl
        whitelist = wl
    }

    /// Latest counters per (domain, ip) pair; records accumulate until the app
    /// exits or the user clears them, so closed flows never vanish from the UI.
    private var visitsByPair: [String: WebsiteVisit] = [:]
    private var lastResetGeneration = 0

    func observe(capture: CaptureController) async {
        while !Task.isCancelled {
            let visits = await capture.websiteVisits()
            guard !Task.isCancelled else { return }
            if capture.resetGeneration != lastResetGeneration {
                lastResetGeneration = capture.resetGeneration
                visitsByPair.removeAll()
            }
            for v in visits { visitsByPair["\(v.domain)|\(v.ip)"] = v }
            let groups = Dictionary(grouping: visitsByPair.values) {
                $0.domain.isEmpty ? "ip:\($0.ip)" : "domain:\($0.domain.lowercased())"
            }
            var values: [WebsiteStat] = []
            for (key, records) in groups {
                let ips = Set(records.map(\.ip)).sorted()
                let tcp = records.reduce(UInt64(0)) { $0 + $1.tcpConnections }
                let udp = records.reduce(UInt64(0)) { $0 + $1.udpFlows }
                values.append(WebsiteStat(id: key, domain: records.first?.domain.lowercased() ?? "",
                                          ips: ips, tcp: tcp, udp: udp,
                                          bytesOut: records.reduce(0) { $0 + $1.bytesOut },
                                          bytesIn: records.reduce(0) { $0 + $1.bytesIn }))
            }
            values.sort { $0.tcp == $1.tcp ? $0.title < $1.title : $0.tcp > $1.tcp }
            if values != websites { websites = values }
            let accumulated = visitsByPair.values.sorted {
                $0.domain == $1.domain ? $0.ip < $1.ip : $0.domain < $1.domain
            }
            if self.visits != accumulated { self.visits = accumulated }
            do { try await Task.sleep(nanoseconds: 3_000_000_000) }
            catch { return }
        }
    }
}

private let chartColors: [Color] = [
    Color(red: 0.10, green: 0.45, blue: 0.91),
    Color(red: 0.06, green: 0.66, blue: 0.60),
    Color(red: 0.96, green: 0.69, blue: 0.26),
    Color(red: 0.53, green: 0.38, blue: 0.85),
    Color(red: 0.93, green: 0.44, blue: 0.52),
    Color(red: 0.60, green: 0.66, blue: 0.73),
]

struct SettingsView: View {
    @ObservedObject var model: WebsiteStatsModel
    @ObservedObject var capture: CaptureController

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("概览").font(.headline).foregroundStyle(.primary)
                    Text(String(format: NSLocalizedString("%lld 个服务 · %lld 次连接 · 已过滤 %lld 个", comment: "summary"), model.websites.count, model.websites.reduce(UInt64(0)) { $0 + $1.tcp + $1.udp }, model.hiddenWebsites.count))
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
                TrafficRank(websites: model.shownWebsites)
                ConnectionPie(websites: model.shownWebsites)
                NavigationLink(value: "map") {
                    HStack(spacing: 14) {
                        Image(systemName: "map.fill")
                            .font(.system(size: 18))
                            .foregroundStyle(Color(red: 0x1A / 255, green: 0x73 / 255, blue: 0xE8 / 255))
                            .frame(width: 40, height: 40)
                            .background(Color(red: 0xE8 / 255, green: 0xF0 / 255, blue: 0xFE / 255),
                                        in: RoundedRectangle(cornerRadius: 12))
                        VStack(alignment: .leading, spacing: 4) {
                            Text("连接分布").font(.headline).foregroundStyle(.primary)
                            Text("连接在世界地图上的分布").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").foregroundStyle(.secondary)
                    }
                    .padding(20)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
                }
                NavigationLink(value: "websites") {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("通信的服务").font(.headline).foregroundStyle(.primary)
                            Text(String(format: NSLocalizedString("%lld 个服务 / 地址", comment: "count"), model.shownWebsites.count))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").foregroundStyle(.secondary)
                    }
                    .padding(20)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
                }
                NavigationLink(value: "privacy") {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("隐私与数据").font(.headline).foregroundStyle(.primary)
                            Text("数据说明 · 清空记录").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").foregroundStyle(.secondary)
                    }
                    .padding(20)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
                }
                Text("本次会话 · 每 3 秒更新\n记录只保存在本机内存，关闭 VPN 后自动清空。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(20)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("连线图志")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
    }
}

func formatBytes(_ bytes: UInt64) -> String {
    if bytes >= 1_073_741_824 { return String(format: "%.1f GB", Double(bytes) / 1_073_741_824) }
    if bytes >= 1_048_576 { return String(format: "%.1f MB", Double(bytes) / 1_048_576) }
    if bytes >= 1024 { return String(format: "%.1f KB", Double(bytes) / 1024) }
    return "\(bytes) B"
}

private struct PieSlice: Equatable {
    let name: String
    let value: UInt64
    let color: Color
}

private func topSlices(_ entries: [(String, UInt64)], other: String) -> [PieSlice] {
    let items = entries.filter { $0.1 > 0 }.sorted { $0.1 > $1.1 }
    var shown = Array(items.prefix(5))
    let remainder = items.dropFirst(5).reduce(UInt64(0)) { $0 + $1.1 }
    if remainder > 0 { shown.append((other, remainder)) }
    return shown.enumerated().map { PieSlice(name: $0.element.0, value: $0.element.1,
                                             color: chartColors[$0.offset]) }
}

private struct ChartCard<Content: View>: View {
    let title: LocalizedStringKey
    let subtitle: String
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title).font(.headline)
            Text(subtitle).font(.subheadline).foregroundStyle(.secondary)
            content
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }
}

private struct TrafficRank: View {
    let websites: [WebsiteStat]
    private var total: UInt64 { websites.reduce(0) { $0 + $1.bytes } }
    private var top: [WebsiteStat] { Array(websites.filter { $0.bytes > 0 }.sorted { $0.bytes > $1.bytes }.prefix(5)) }

    var body: some View {
        ChartCard(title: "通信量排行", subtitle: String(format: NSLocalizedString("合计 %@", comment: "total"), formatBytes(total))) {
            if total == 0 { Text("暂无 TCP 连接").foregroundStyle(.secondary).frame(maxWidth: .infinity) }
            ForEach(Array(top.enumerated()), id: \.element.id) { index, website in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(website.title).font(.caption).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text(formatBytes(website.bytes)).font(.caption).foregroundStyle(.secondary)
                    }
                    GeometryReader { proxy in
                        ZStack(alignment: .leading) {
                            RoundedRectangle(cornerRadius: 4).fill(Color(.systemGray5))
                            RoundedRectangle(cornerRadius: 4).fill(chartColors[index % chartColors.count])
                                .frame(width: proxy.size.width * CGFloat(website.bytes) / CGFloat(top[0].bytes))
                        }
                    }
                    .frame(height: 8)
                    Text(String(format: NSLocalizedString("上行 %@ · 下行 %@", comment: "traffic"), formatBytes(website.bytesOut), formatBytes(website.bytesIn)))
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// Plain pie with a legend below (name + percentage).
private struct LegendPie: View {
    let title: LocalizedStringKey
    let subtitle: String
    let empty: LocalizedStringKey
    let slices: [PieSlice]
    private var total: UInt64 { slices.reduce(0) { $0 + $1.value } }

    var body: some View {
        ChartCard(title: title, subtitle: subtitle) {
            if total == 0 {
                Text(empty).foregroundStyle(.secondary).frame(maxWidth: .infinity)
            } else {
                Canvas { context, size in
                    let center = CGPoint(x: size.width / 2, y: size.height / 2)
                    let radius = min(size.width, size.height) / 2
                    var start = -90.0
                    for slice in slices {
                        let end = start + Double(slice.value) / Double(total) * 360
                        var path = Path()
                        path.move(to: center)
                        path.addArc(center: center, radius: radius, startAngle: .degrees(start),
                                    endAngle: .degrees(end), clockwise: false)
                        path.closeSubpath()
                        context.fill(path, with: .color(slice.color))
                        start = end
                    }
                }
                .frame(width: 160, height: 160)
                .frame(maxWidth: .infinity)
                .accessibilityLabel(subtitle)
                ForEach(Array(slices.enumerated()), id: \.offset) { index, slice in
                    HStack(spacing: 10) {
                        RoundedRectangle(cornerRadius: 3).fill(slice.color).frame(width: 10, height: 10)
                        Text(slice.name).font(.caption).lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 4)
                        Text(String(format: NSLocalizedString("%lld 次 · %.1f%%", comment: "slice"), Int64(slice.value), Double(slice.value) / Double(total) * 100))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}

private struct ConnectionPie: View {
    let websites: [WebsiteStat]
    private var total: UInt64 { websites.reduce(0) { $0 + $1.tcp + $1.udp } }
    var body: some View {
        LegendPie(title: "服务分布", subtitle: String(format: NSLocalizedString("累计 %lld 个连接", comment: "total"), Int64(total)), empty: "暂无连接",
                  slices: topSlices(websites.map { ($0.title, $0.tcp + $0.udp) }, other: String(localized: "其他服务")))
    }
}

struct WebsitesView: View {
    @ObservedObject var model: WebsiteStatsModel
    var hidden = false
    @State private var query = ""
    private var source: [WebsiteStat] { hidden ? model.hiddenWebsites : model.shownWebsites }
    private var filtered: [WebsiteStat] {
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return source.filter {
            term.isEmpty || $0.title.localizedCaseInsensitiveContains(term)
                || $0.ips.contains { $0.localizedCaseInsensitiveContains(term) }
        }
    }

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 4) {
                    Text("概览").font(.subheadline.weight(.semibold))
                        .foregroundStyle(Color(red: 0x1A / 255, green: 0x73 / 255, blue: 0xE8 / 255))
                    if hidden {
                        Text(String(format: NSLocalizedString("%lld 个连接被白名单隐藏", comment: "filtered"), source.count)).font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text(String(format: NSLocalizedString("%lld 个服务 · %lld 次连接 · 已过滤 %lld 个", comment: "summary"), model.websites.count, model.websites.reduce(UInt64(0)) { $0 + $1.tcp + $1.udp }, model.hiddenWebsites.count))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)
            }
            Section {
                if filtered.isEmpty {
                    if query.isEmpty {
                        Text(hidden ? "没有被白名单隐藏的连接" : "本次会话还没有连接记录").foregroundStyle(.secondary)
                    } else {
                        Text("没有匹配的域名或 IP").foregroundStyle(.secondary)
                    }
                }
                ForEach(filtered) { website in
                    NavigationLink(value: website) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(website.title).font(.subheadline.weight(.semibold))
                            if website.domain.isEmpty {
                                Text("未标注服务名").font(.caption).foregroundStyle(.secondary)
                            } else {
                                Text(website.ips.joined(separator: "\n")).font(.caption).foregroundStyle(.secondary)
                            }
                            Text(String(format: NSLocalizedString("TCP %lld 次 · UDP %lld 个流", comment: "flows"), Int64(website.tcp), Int64(website.udp))).font(.caption).foregroundStyle(.blue)
                        }
                        .textSelection(.enabled)
                        .padding(.vertical, 6)
                    }
                }
                if !hidden && !model.hiddenWebsites.isEmpty {
                    NavigationLink(value: "filtered") {
                        HStack {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("已过滤的服务").font(.subheadline.weight(.semibold))
                                Text(String(format: NSLocalizedString("%lld 个连接被白名单隐藏", comment: "filtered"), model.hiddenWebsites.count))
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                        .padding(.vertical, 6)
                    }
                }
            } header: {
                Text(String(format: NSLocalizedString("%lld 个服务 / 地址", comment: "count"), filtered.count))
            }
        }
        .searchable(text: $query, prompt: "搜索域名或 IP")
        .navigationTitle(hidden ? "已过滤的服务" : "通信的服务")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
    }
}
