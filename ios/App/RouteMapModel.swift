import CoreLocation
import Foundation
import SwiftUI

struct RouteDestination {
    let ip: String
    let label: String
    let coordinate: CLLocationCoordinate2D
    let hasDomain: Bool
}

struct RouteMarker {
    let coordinate: CLLocationCoordinate2D
    let label: String
    let hasDomain: Bool
}

/// Renderer-agnostic route data; the map view turns these into overlays.
struct RouteSnapshot {
    var lines: [[CLLocationCoordinate2D]] = []
    var markers: [RouteMarker] = []
    var sw: CLLocationCoordinate2D?
    var ne: CLLocationCoordinate2D?
}

@MainActor
final class RouteMapModel: ObservableObject {
    @Published var origin: CLLocationCoordinate2D?
    @Published var locationDenied = false
    @Published private(set) var centerRequest = 0

    /// Bottom-right location button: re-center the map on the phone's position.
    func recenter() { centerRequest += 1 }
    @Published var snapshot = RouteSnapshot()
    @Published var attribution = ""
    @Published private(set) var renderRevision = 0

    private let capture: CaptureController
    private let resolver: GeoResolver
    private var refreshTask: Task<Void, Never>?
    private var requestId: UInt64 = 0
    /// Traffic records accumulate until the app exits or the user clears them:
    /// a destination once observed stays on the map even after its flows close.
    private var chosenNames: [String: String] = [:]
    private var nameUsedByIp: [String: String] = [:]
    private var destinationsByIp: [String: RouteDestination] = [:]
    private var drawnOrigin: CLLocationCoordinate2D?
    private var lastResetGeneration = 0

    init(capture: CaptureController, resolver: GeoResolver = DbIpGeoResolver()) {
        self.capture = capture
        self.resolver = resolver
    }

    deinit {
        refreshTask?.cancel()
    }

    func start() {
        guard refreshTask == nil else { return }
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.refresh()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    private func refresh() async {
        guard let origin else { return }
        if capture.resetGeneration != lastResetGeneration {
            lastResetGeneration = capture.resetGeneration
            chosenNames.removeAll()
            nameUsedByIp.removeAll()
            destinationsByIp.removeAll()
            drawnOrigin = nil
        }
        let observations = await capture.externalDestinations()
        for (ip, flows) in Dictionary(grouping: observations, by: \.ip) {
            let name = flows.map { $0.domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .filter { !$0.isEmpty }.min() ?? ""
            if let old = chosenNames[ip], !old.isEmpty { continue }
            chosenNames[ip] = name
        }
        let pending = chosenNames.keys.filter { nameUsedByIp[$0] != chosenNames[$0] }.sorted()
        var dirty = false
        if !pending.isEmpty {
            let locale = GeoRequest.systemLocale
            let requests = pending.map {
                requestId += 1
                return GeoRequest(requestId: requestId, ipVersion: $0.contains(":") ? 6 : 4,
                                  address: $0, fields: [.country, .city], locale: locale)
            }
            let requestById = Dictionary(uniqueKeysWithValues: requests.map { ($0.requestId, $0.address) })
            for result in await resolver.resolve(requests) {
                guard let ip = requestById[result.requestId], let name = chosenNames[ip],
                      result.status != .unavailable else { continue }
                nameUsedByIp[ip] = name
                guard case .hit = result.status,
                      let latitude = result.latitude,
                      let longitude = result.longitude else { continue }
                let title = name.isEmpty ? ip : name
                let geo = result.city ?? result.countryName ?? ""
                destinationsByIp[ip] = RouteDestination(
                    ip: ip,
                    label: geo.isEmpty ? title : "\(geo)(\(title))",
                    coordinate: CLLocationCoordinate2D(latitude: latitude, longitude: longitude),
                    hasDomain: !name.isEmpty)
                dirty = true
            }
        }
        let moved = drawnOrigin.map {
            abs($0.latitude - origin.latitude) > 0.0001 ||
                abs($0.longitude - origin.longitude) > 0.0001
        } ?? true
        if dirty || moved {
            drawRoutes(from: origin, to: destinationsByIp.values.sorted { $0.ip < $1.ip })
            drawnOrigin = origin
        }
        attribution = destinationsByIp.isEmpty ? "" : DbIpGeoResolver.attribution
    }

    private func drawRoutes(from origin: CLLocationCoordinate2D, to destinations: [RouteDestination]) {
        var next = RouteSnapshot()
        // IPs geolocating to the same city coordinate would draw identical,
        // perfectly overlapping arcs — fan them out slightly so each
        // destination keeps its own visible line and label.
        var groups: [Int64: [Int]] = [:]
        func cell(_ c: CLLocationCoordinate2D) -> Int64 {
            Int64((c.latitude * 4).rounded()) * 1000 + Int64((c.longitude * 4).rounded())
        }
        for (index, destination) in destinations.enumerated() {
            groups[cell(destination.coordinate), default: []].append(index)
        }
        for (index, destination) in destinations.enumerated() {
            var end = destination.coordinate
            let siblings = groups[cell(end)] ?? []
            if siblings.count > 1, let order = siblings.firstIndex(of: index), order > 0 {
                let angle = 2 * Double.pi * Double(order) / Double(siblings.count)
                let radius = 0.35
                end = CLLocationCoordinate2D(
                    latitude: max(-85, min(85, end.latitude + radius * sin(angle))),
                    longitude: end.longitude +
                        radius * cos(angle) / max(0.2, cos(end.latitude * .pi / 180)))
            }
            let points = Self.greatCircle(from: origin, to: end)
            var segment = [CLLocationCoordinate2D]()
            var previous: CLLocationCoordinate2D?
            for point in points {
                if let previous, abs(point.longitude - previous.longitude) > 180 {
                    if segment.count > 1 {
                        next.lines.append(segment)
                    }
                    segment.removeAll()
                }
                segment.append(point)
                previous = point
            }
            if segment.count > 1 {
                next.lines.append(segment)
            }
            next.markers.append(RouteMarker(coordinate: end,
                                            label: destination.label,
                                            hasDomain: destination.hasDomain))
        }
        if !destinations.isEmpty {
            var latitudeDelta = 0.0
            var longitudeDelta = 0.0
            for destination in destinations {
                var delta = destination.coordinate.longitude - origin.longitude
                while delta > 180 { delta -= 360 }
                while delta < -180 { delta += 360 }
                longitudeDelta = max(longitudeDelta, abs(delta))
                latitudeDelta = max(latitudeDelta, abs(destination.coordinate.latitude - origin.latitude))
            }
            next.sw = CLLocationCoordinate2D(latitude: origin.latitude - latitudeDelta * 1.15,
                                             longitude: origin.longitude - longitudeDelta * 1.15)
            next.ne = CLLocationCoordinate2D(latitude: origin.latitude + latitudeDelta * 1.15,
                                             longitude: origin.longitude + longitudeDelta * 1.15)
        }
        snapshot = next
        renderRevision += 1
    }

    private static func greatCircle(from start: CLLocationCoordinate2D,
                                    to end: CLLocationCoordinate2D) -> [CLLocationCoordinate2D] {
        let lat1 = start.latitude * .pi / 180, lon1 = start.longitude * .pi / 180
        let lat2 = end.latitude * .pi / 180, lon2 = end.longitude * .pi / 180
        let a = sin((lat2 - lat1) / 2), b = sin((lon2 - lon1) / 2)
        let delta = 2 * asin(sqrt(a * a + cos(lat1) * cos(lat2) * b * b))
        guard delta > 0.0001 else { return [start, end] }
        let steps = min(96, max(16, Int(delta * 180 / .pi / 2)))
        // Bow perpendicular to the route direction so north-south routes curve
        // sideways instead of overshooting latitude. Lift vanishes at the ends.
        var dLon = (lon2 - lon1) * 180 / .pi
        if dLon > 180 { dLon -= 360 } else if dLon < -180 { dLon += 360 }
        let dLat = (lat2 - lat1) * 180 / .pi
        let norm = max(0.001, sqrt(dLat * dLat + dLon * dLon))
        let perpLat = -dLon / norm, perpLon = dLat / norm
        let lift = min(5.0, delta * 180 / .pi * 0.03)
        return (0...steps).map { step in
            let f = Double(step) / Double(steps)
            let x = sin((1 - f) * delta) / sin(delta) * cos(lat1) * cos(lon1) +
                sin(f * delta) / sin(delta) * cos(lat2) * cos(lon2)
            let y = sin((1 - f) * delta) / sin(delta) * cos(lat1) * sin(lon1) +
                sin(f * delta) / sin(delta) * cos(lat2) * sin(lon2)
            let z = sin((1 - f) * delta) / sin(delta) * sin(lat1) +
                sin(f * delta) / sin(delta) * sin(lat2)
            let k = lift * sin(.pi * f)
            let lat = atan2(z, sqrt(x * x + y * y)) * 180 / .pi + k * perpLat
            let lon = atan2(y, x) * 180 / .pi + k * perpLon
            return CLLocationCoordinate2D(latitude: min(85.0, max(-85.0, lat)),
                                        longitude: lon)
        }
    }
}
