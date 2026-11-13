import SwiftUI
import Network

/// Detail page for a contacted service. Shows local enrichment immediately,
/// sends a lookup request, and on 402 presents purchase options.
struct LookupDetailView: View {
    let website: WebsiteStat
    let stats: WebsiteStatsModel

    @StateObject private var billing = LookupBilling.shared
    @State private var state: String
    @State private var result: [String: Any] = [:]
    @State private var checkoutEnabled = false
    @State private var waitingForPurchase = false
    @State private var lastCreditSequence = 0
    @AppStorage("lookup_consent") private var consent = false

    private var api: LookupServiceClient? { LookupServiceClient.shared }

    init(website: WebsiteStat, stats: WebsiteStatsModel) {
        self.website = website
        self.stats = stats
        _state = State(initialValue:
            UserDefaults.standard.bool(forKey: "lookup_consent") ? "loading" : "idle")
    }

    var body: some View {
        List {
            // Local info
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text(website.title)
                        .font(.title3.weight(.semibold))
                    if !website.ips.isEmpty {
                        Text(website.ips.joined(separator: "\n"))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text(String(format: NSLocalizedString("TCP %lld 次 · UDP %lld 个流", comment: "flows"), Int64(website.tcp), Int64(website.udp)))
                        .font(.caption)
                        .foregroundStyle(.blue)
                    Text("↑ \(formatBytes(website.bytesOut)) · ↓ \(formatBytes(website.bytesIn))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            // AI insight
            Section(header: Text(String(localized: "服务解读"))) {
                if !consent {
                    consentSection
                } else {
                    stateSection
                    if state == "purchase" { purchaseSection }
                    retrySection
                    restoreSection
                }
            }

            if state == "done" {
                ForEach(insightGroups, id: \.title) { group in
                    Section(header: Text(group.title)) {
                        Text(group.lines.joined(separator: "\n"))
                            .font(.body)
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle(String(localized: "连接详情"))
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await setupAndQuery()
        }
        .task { await stats.refreshWhitelist() }
        .onChange(of: billing.purchaseState) { newState in
            handlePurchaseStateChange(newState)
        }
    }

    // MARK: - Sections

    private var consentSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(String(localized: "查询该连接的服务归属需要将域名或 IP 发送给服务器；不会上传流量内容、完整 URL 或进程信息。"))
                .font(.caption)
                .foregroundStyle(.secondary)
            Button(String(localized: "继续查询")) {
                consent = true
                Task { await query() }
            }
            .buttonStyle(.borderedProminent)
        }
    }

    @ViewBuilder
    private var stateSection: some View {
        switch state {
        case "loading":
            HStack(spacing: 8) {
                ProgressView()
                Text(String(localized: "正在查询…"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case "done":
            EmptyView()
        case "private":
            Text(String(localized: "本地 IP 没有更多信息"))
                .font(.caption)
                .foregroundStyle(.secondary)
        case "busy":
            Text(String(localized: "请求过于频繁，请稍后重试"))
                .font(.caption)
                .foregroundStyle(.secondary)
        case "expired_request":
            Text(String(localized: "该查询已过期，请返回后重新进入"))
                .font(.caption)
                .foregroundStyle(.secondary)
        case "purchase":
            Text(String(localized: "查看解读需要购买"))
                .font(.caption)
                .foregroundStyle(.secondary)
        default:
            Text(String(localized: "查询暂时不可用，请稍后重试"))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var purchaseSection: some View {
        VStack(spacing: 8) {
            if !checkoutEnabled {
                Text(String(localized: "购买尚未开通"))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            if showsPurchaseStatus(billing.purchaseState) {
                Text(purchaseStatusText)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            purchaseButton(productId: LookupBilling.singleProductID, label: String(localized: "单次查询"))
            purchaseButton(productId: LookupBilling.proProductID, label: String(localized: "专业版 · 月付"))
            purchaseButton(productId: LookupBilling.proYearProductID, label: String(localized: "专业版 · 年付"))

            Text(String(localized: "专业版按月或按年自动续订，可随时在商店管理页面取消；取消后当期仍有效"))
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
    }

    private func purchaseButton(productId: String, label: String) -> some View {
        let price = billing.price(for: productId)
        let enabled = checkoutEnabled && price != nil
            && !isProcessing(billing.purchaseState) && !waitingForPurchase
        return Button {
            waitingForPurchase = true
            Task { await billing.buy(productId: productId) }
        } label: {
            HStack {
                Text(label)
                Spacer()
                if let price { Text(price).foregroundStyle(.secondary) }
            }
        }
        .buttonStyle(.bordered)
        .disabled(!enabled)
    }

    @ViewBuilder
    private var retrySection: some View {
        if state != "loading" && state != "done" && state != "private" && state != "expired_request" {
            Button(String(localized: "重试")) {
                Task { await query() }
            }
            .font(.caption)
        }
    }

    @ViewBuilder
    private var restoreSection: some View {
        if api != nil {
            Button(String(localized: "恢复购买")) {
                Task { await billing.restorePurchases() }
            }
            .font(.caption)
            .disabled(isProcessing(billing.purchaseState))
        }
    }

    // MARK: - Result

    private struct InsightGroup {
        let title: String
        let lines: [String]
    }

    private var insightGroups: [InsightGroup] {
        func pick(_ key: String) -> String? {
            guard let value = nonEmpty(result[key]), value != "unknown" else { return nil }
            return value
        }
        let groups = [
            InsightGroup(title: String(localized: "目标"),
                         lines: [targetText, pick("registrable")].compactMap { $0 }),
            InsightGroup(title: String(localized: "位置"),
                         lines: [pick("location")].compactMap { $0 }),
            InsightGroup(title: String(localized: "服务"),
                         lines: [pick("service"), pick("owner") ?? pick("company"),
                                 pick("category").map(categoryLabel)].compactMap { $0 }),
            InsightGroup(title: String(localized: "安全等级"),
                         lines: [pick("risk").map(riskLabel),
                                 pick("confidence").map(confidenceLabel)].compactMap { $0 }),
            InsightGroup(title: String(localized: "解读"),
                         lines: [nonEmpty(result["summary"])].compactMap { $0 }),
        ]
        return groups.filter { !$0.lines.isEmpty }
    }

    private var targetText: String {
        var parts = [website.domain]
        parts.append(contentsOf: website.ips)
        return parts.filter { !$0.isEmpty }.joined(separator: "\n")
    }

    private func nonEmpty(_ value: Any?) -> String? {
        guard let text = value as? String, !text.isEmpty else { return nil }
        return text
    }

    private func riskLabel(_ risk: String) -> String {
        switch risk {
        case "low": return String(localized: "低风险")
        case "medium": return String(localized: "中风险")
        case "high": return String(localized: "高风险")
        default: return String(localized: "未知")
        }
    }

    private func confidenceLabel(_ confidence: String) -> String {
        switch confidence {
        case "high": return String(localized: "置信度高")
        case "medium": return String(localized: "置信度中")
        case "low": return String(localized: "置信度低")
        default: return String(localized: "未知")
        }
    }

    private func categoryLabel(_ category: String) -> String {
        switch category {
        case "cdn": return "CDN"
        case "cloud": return String(localized: "云服务")
        case "ads": return String(localized: "广告")
        case "telemetry": return String(localized: "遥测")
        case "social": return String(localized: "社交")
        case "mail": return String(localized: "邮件")
        case "streaming": return String(localized: "流媒体")
        case "os_vendor": return String(localized: "系统厂商")
        case "iot": return String(localized: "物联网")
        case "dev": return String(localized: "开发者服务")
        case "security": return String(localized: "安全服务")
        default: return String(localized: "其他")
        }
    }

    // MARK: - Logic

    private func setupAndQuery() async {
        guard consent else { return }
        do {
            let config = try await api?.config()
            checkoutEnabled = config?["purchases_enabled"] as? Bool == true
                && config?["store_ready"] as? Bool == true
            NSLog("[Lookup] config: \(config ?? [:]), checkout=\(checkoutEnabled)")
            if checkoutEnabled { await billing.loadProducts() }
            await billing.restorePurchases()
        } catch {
            checkoutEnabled = false
        }
        if state != "done" { await query() }
    }

    private func query() async {
        guard let api else { state = "unavailable"; return }
        state = "loading"
        do {
            let domain = normalizeDomain(website.domain)
            // One target per lookup: a named service queries its domain only;
            // an IP-only entry queries its single public address.
            let ips = domain.isEmpty ? Array(website.ips.filter(isPublicIP).prefix(1)) : []
            if isPrivateDomain(domain) || (domain.isEmpty && ips.isEmpty) {
                state = "private"
                return
            }

            let body: [String: Any] = [
                "request_id": UUID().uuidString,
                "query": [
                    "domain": domain,
                    "ips": Array(ips)
                ],
                "lang": Locale.current.language.languageCode == "zh" ? "zh" : "en",
                "schema": 3
            ]

            let response = try await api.request(path: "/v1/lookupaddress/lookup", body: body)
            if let resultDict = response["result"] as? [String: Any],
               resultDict["summary"] is String {
                result = resultDict
                state = "done"
            } else {
                state = "unavailable"
            }
        } catch let error as LookupServiceClient.ApiFailure {
            switch error.code {
            case 1003: state = "purchase"
            case 1007, 1011: state = "busy"
            case 1013: state = "expired_request"
            case 1001: state = "private"
            default: state = "unavailable"
            }
        } catch {
            state = "unavailable"
        }
    }

    private func handlePurchaseStateChange(_ newState: LookupBilling.PurchaseState) {
        if case .credited(let sequence) = newState, sequence != lastCreditSequence {
            lastCreditSequence = sequence
            if waitingForPurchase {
                waitingForPurchase = false
                Task { await query() }
            }
        }
        switch newState {
        case .cancelled, .failed, .expired:
            waitingForPurchase = false
        default: break
        }
    }

    // MARK: - Helpers

    private func isProcessing(_ state: LookupBilling.PurchaseState) -> Bool {
        switch state {
        case .paying, .verifying, .pending: return true
        default: return false
        }
    }

    private func showsPurchaseStatus(_ state: LookupBilling.PurchaseState) -> Bool {
        switch state {
        case .paying, .verifying, .pending, .failed, .expired: return true
        default: return false
        }
    }

    private var purchaseStatusText: String {
        switch billing.purchaseState {
        case .paying: return String(localized: "支付中…")
        case .verifying: return String(localized: "验证购买中…")
        case .pending: return String(localized: "支付处理中，稍后自动到账")
        case .expired: return String(localized: "购买已失效")
        case .failed: return String(localized: "购买验证失败，可重试验证")
        default: return ""
        }
    }

    private func normalizeDomain(_ raw: String) -> String {
        var domain = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if domain.hasSuffix(".") { domain.removeLast() }
        return domain
    }

    private func isPrivateDomain(_ domain: String) -> Bool {
        let suffixes = [".local", ".localhost", ".internal", ".home.arpa", ".invalid", ".test"]
        return suffixes.contains { domain.hasSuffix($0) }
    }

    private func isPublicV4(_ b: [UInt8]) -> Bool {
        guard b.count == 4 else { return false }
        if b[0] == 0 || b[0] >= 224 || b[0] == 127 || b[0] == 10 { return false }
        if b[0] == 100 && (64...127).contains(b[1]) { return false }
        if b[0] == 192 && b[1] == 0 { return false }
        if b[0] == 198 && (b[1] == 18 || b[1] == 19) { return false }
        if b[0] == 198 && b[1] == 51 && b[2] == 100 { return false }
        if b[0] == 203 && b[1] == 0 && b[2] == 113 { return false }
        return true
    }

    private func isPublicIP(_ raw: String) -> Bool {
        var addr = in_addr()
        var addr6 = in6_addr()
        let isV4 = inet_pton(AF_INET, raw, &addr) == 1
        if isV4 {
            return isPublicV4(withUnsafeBytes(of: &addr) { Array($0) })
        }
        let isV6 = inet_pton(AF_INET6, raw, &addr6) == 1
        if isV6 {
            let b = withUnsafeBytes(of: &addr6) { Array($0) }
            guard b.count == 16 else { return false }
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) follows the IPv4 rules.
            if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff {
                return isPublicV4(Array(b.suffix(4)))
            }
            // Keep in sync with the server's publicAddress: 2000::/3 global
            // unicast, excluding Teredo (2001::/32), 6to4 (2002::/16) and
            // documentation (2001:db8::/32) ranges.
            guard b[0] >= 0x20 && b[0] <= 0x3f else { return false }
            if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00 { return false }
            if b[0] == 0x20 && b[1] == 0x02 { return false }
            if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 { return false }
            return true
        }
        return false
    }
}

