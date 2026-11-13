import Foundation

/// UI-side destination enrichment. It never mutates DPI flow summaries.
enum GeoField: Hashable {
    case country, city, asn
}

enum GeoStatus {
    case hit, miss, unavailable
}

struct GeoRequest: Hashable {
    let requestId: UInt64
    let ipVersion: UInt8
    let address: String
    let fields: Set<GeoField>
    var locale: String = GeoRequest.systemLocale

    static var systemLocale: String {
        let preferred = Locale(identifier: Locale.preferredLanguages.first ?? Locale.current.identifier)
        let language = preferred.language.languageCode?.identifier ?? "en"
        // DB-IP uses these regional keys for its Chinese and Portuguese names.
        switch language {
        case "zh": return "zh-CN"
        case "pt": return "pt-BR"
        default: return language
        }
    }
}

struct GeoResult {
    let requestId: UInt64
    var status: GeoStatus
    var countryCode: String?
    var countryName: String?
    var region: String?
    var city: String?
    var latitude: Double?
    var longitude: Double?
    var asn: UInt64?
    var org: String?
    let source: String
    let attribution: String
    var approximate = true
}

protocol GeoResolver {
    func resolve(_ requests: [GeoRequest]) async -> [GeoResult]
}

actor DbIpGeoResolver: GeoResolver {
    static let attribution = "IP Geolocation by DB-IP · City names by GeoNames"
    private let cityDatabase: UnsafeMutableRawPointer?
    private let asnDatabase: UnsafeMutableRawPointer?
    private struct CacheEntry {
        let fields: Set<GeoField>
        let locale: String
        let result: GeoResult
    }
    private var cache: [String: CacheEntry] = [:]

    init() {
        cityDatabase = Bundle.main.path(forResource: "dbip-city-lite", ofType: "mmdb")
            .flatMap { linkatlasGeoOpen($0) }
        asnDatabase = Bundle.main.path(forResource: "dbip-asn-lite", ofType: "mmdb")
            .flatMap { linkatlasGeoOpen($0) }
    }

    deinit {
        linkatlasGeoClose(cityDatabase)
        linkatlasGeoClose(asnDatabase)
    }

    func resolve(_ requests: [GeoRequest]) async -> [GeoResult] {
        requests.map { lookup($0) }
    }

    private func lookup(_ request: GeoRequest) -> GeoResult {
        if let cached = cache[request.address],
           cached.fields == request.fields, cached.locale == request.locale {
            let result = cached.result
            return GeoResult(requestId: request.requestId, status: result.status,
                             countryCode: result.countryCode, countryName: result.countryName,
                             region: result.region, city: result.city, latitude: result.latitude,
                             longitude: result.longitude, asn: result.asn, org: result.org,
                             source: result.source, attribution: result.attribution,
                             approximate: result.approximate)
        }
        var result = GeoResult(requestId: request.requestId, status: .miss,
                               source: "dbip_local", attribution: Self.attribution)
        if ((request.fields.contains(.city) || request.fields.contains(.country)) && cityDatabase == nil)
            || (request.fields.contains(.asn) && asnDatabase == nil) {
            result.status = .unavailable
            return result
        }
        var record = LinkAtlasGeoLookup()
        if request.fields.contains(.city) || request.fields.contains(.country),
           let cityDatabase,
           linkatlasGeoLookup(cityDatabase, request.address, request.locale, &record),
           record.status == 1 {
            result.status = .hit
            result.countryCode = string(record.countryCode)
            result.countryName = string(record.countryName)
            result.region = string(record.region)
            result.city = string(record.city)
            result.latitude = record.hasLatitude ? record.latitude : nil
            result.longitude = record.hasLongitude ? record.longitude : nil
        }
        var asnRecord = LinkAtlasGeoLookup()
        if request.fields.contains(.asn),
           let asnDatabase,
           linkatlasGeoLookup(asnDatabase, request.address, request.locale, &asnRecord),
           asnRecord.status == 1 {
            result.status = .hit
            result.asn = asnRecord.asn == 0 ? nil : asnRecord.asn
            result.org = string(asnRecord.organization)
        }
        if result.status != .unavailable {
            if cache.count >= 2048, cache[request.address] == nil, let key = cache.keys.first {
                cache.removeValue(forKey: key)
            }
            cache[request.address] = CacheEntry(fields: request.fields, locale: request.locale, result: result)
        }
        return result
    }

    private func string<T>(_ tuple: T) -> String? {
        let value = withUnsafeBytes(of: tuple) { bytes -> String? in
            guard let base = bytes.baseAddress else { return nil }
            return String(validatingCString: base.assumingMemoryBound(to: CChar.self))
        }
        return value?.isEmpty == false ? value : nil
    }
}
