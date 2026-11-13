import Foundation

/// Server-provided list of destinations hidden from every screen; the user can
/// still inspect them through the "filtered" entry in the services list.
struct ServiceWhitelist: Codable {
    var domains: [String] = []
    var ips: [String] = []

    var isEmpty: Bool { domains.isEmpty && ips.isEmpty }

    func matches(_ website: WebsiteStat) -> Bool {
        if !website.domain.isEmpty &&
            domains.contains(where: { domainMatches($0, website.domain) }) {
            return true
        }
        return !website.ips.isEmpty && website.ips.allSatisfy { ip in
            ips.contains { ipMatches($0, ip) }
        }
    }

    // "a.b.c.*" is a /24 prefix match; anything else must match exactly.
    private func ipMatches(_ pattern: String, _ ip: String) -> Bool {
        if pattern.hasSuffix(".*") { return ip.hasPrefix(String(pattern.dropLast(1))) }
        return ip == pattern
    }

    // "*" matches one or more labels including deeper subdomains; a leading
    // "*." also matches the bare remainder (e.g. "*.youtube.com" hits youtube.com).
    private func domainMatches(_ pattern: String, _ domain: String) -> Bool {
        if !pattern.contains("*") {
            return domain == pattern || domain.hasSuffix("." + pattern)
        }
        let body = pattern.split(separator: ".").map {
            $0 == "*" ? ".+" : NSRegularExpression.escapedPattern(for: String($0))
        }.joined(separator: "\\.")
        if domain.range(of: "^\(body)$", options: .regularExpression) != nil { return true }
        return pattern.hasPrefix("*.") && domainMatches(String(pattern.dropFirst(2)), domain)
    }

    static let empty = ServiceWhitelist()

    private static let key = "whitelist_v1"

    static var stored: ServiceWhitelist {
        get {
            guard let data = UserDefaults.standard.data(forKey: key),
                  let wl = try? JSONDecoder().decode(ServiceWhitelist.self, from: data) else {
                return .empty
            }
            return wl
        }
        set {
            UserDefaults.standard.set(try? JSONEncoder().encode(newValue), forKey: key)
        }
    }
}
