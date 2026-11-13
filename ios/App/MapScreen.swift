import CoreLocation
import MapKit
import SwiftUI
import UIKit

/// Shows active public destinations as arcing routes from the user's location.
struct MapScreen: UIViewRepresentable {
    @ObservedObject var model: RouteMapModel

    func makeCoordinator() -> Coordinator { Coordinator(model: model) }

    func makeUIView(context: Context) -> MKMapView {
        let map = MKMapView()
        map.delegate = context.coordinator
        context.coordinator.configureLocation(on: map)
        map.setCenter(CLLocationCoordinate2D(latitude: 20, longitude: 0), animated: false)
        return map
    }

    func updateUIView(_ map: MKMapView, context: Context) {
        context.coordinator.model = model
        context.coordinator.updateShapes(on: map)
        context.coordinator.applyCenterRequest(on: map)
    }

    static func dismantleUIView(_ map: MKMapView, coordinator: Coordinator) {
        coordinator.stopLocation()
        map.delegate = nil
    }

    private final class RouteAnnotation: NSObject, MKAnnotation {
        let coordinate: CLLocationCoordinate2D
        let label: String
        init(marker: RouteMarker) {
            coordinate = marker.coordinate
            label = marker.label
        }
    }

    @MainActor
    final class Coordinator: NSObject, MKMapViewDelegate, CLLocationManagerDelegate {
        var model: RouteMapModel
        private let locationManager = CLLocationManager()
        private weak var mapView: MKMapView?
        private var didFly = false
        private var renderedRevision = -1
        private var lastCenterRequest = 0
        private var polylineRenderers: [ObjectIdentifier: MKPolylineRenderer] = [:]
        private var flowTimer: Timer?
        private var dashPhase: CGFloat = 0

        init(model: RouteMapModel) { self.model = model }

        func configureLocation(on map: MKMapView) {
            mapView = map
            locationManager.delegate = self
            locationManager.desiredAccuracy = kCLLocationAccuracyKilometer
            locationManager.distanceFilter = 1000
            locationManagerDidChangeAuthorization(locationManager)
            flowTimer = Timer.scheduledTimer(withTimeInterval: 0.06, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.tickFlow() }
            }
        }

        func stopLocation() {
            locationManager.stopUpdatingLocation()
            locationManager.delegate = nil
            flowTimer?.invalidate()
            flowTimer = nil
        }

        /// Advances the dash phase so route dashes march outward, from the
        /// phone's position toward each destination.
        private func tickFlow() {
            guard !polylineRenderers.isEmpty else { return }
            dashPhase -= 8
            for renderer in polylineRenderers.values {
                renderer.lineDashPhase = dashPhase
                renderer.setNeedsDisplay()
            }
        }

        func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
            let status = manager.authorizationStatus
            // Delegate callbacks may arrive during UIViewRepresentable updates.
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.model.locationDenied = status == .denied || status == .restricted
                switch status {
                case .authorizedAlways, .authorizedWhenInUse:
                    self.mapView?.showsUserLocation = true
                    manager.startUpdatingLocation()
                default:
                    manager.stopUpdatingLocation()
                    self.mapView?.showsUserLocation = false
                    self.model.origin = nil
                    self.mapView?.removeOverlays(self.mapView?.overlays ?? [])
                }
            }
        }

        func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
            guard let location = locations.last, location.horizontalAccuracy >= 0,
                  let mapView else { return }
            updateOrigin(location.coordinate, on: mapView)
        }

        func mapView(_ mapView: MKMapView, didUpdate userLocation: MKUserLocation) {
            guard let location = userLocation.location, location.horizontalAccuracy >= 0 else { return }
            updateOrigin(location.coordinate, on: mapView)
        }

        private func updateOrigin(_ coordinate: CLLocationCoordinate2D, on mapView: MKMapView) {
            guard CLLocationCoordinate2DIsValid(coordinate) else { return }
            model.origin = coordinate
            // Center on the user's location once on entry; afterwards the user
            // controls the camera — later fixes and route updates must not
            // snap the map back to the phone.
            guard !didFly else { return }
            didFly = true
            mapView.setRegion(MKCoordinateRegion(center: coordinate,
                                                 span: MKCoordinateSpan(latitudeDelta: 40, longitudeDelta: 40)),
                              animated: true)
        }

        func updateShapes(on mapView: MKMapView) {
            guard model.origin != nil else {
                mapView.removeOverlays(mapView.overlays)
                mapView.removeAnnotations(mapView.annotations.filter { $0 is RouteAnnotation })
                polylineRenderers.removeAll()
                renderedRevision = -1
                return
            }
            guard renderedRevision != model.renderRevision else { return }
            renderedRevision = model.renderRevision
            mapView.removeOverlays(mapView.overlays)
            mapView.removeAnnotations(mapView.annotations.filter { $0 is RouteAnnotation })
            polylineRenderers.removeAll()
            for line in model.snapshot.lines {
                line.withUnsafeBufferPointer { buffer in
                    mapView.addOverlay(MKPolyline(coordinates: buffer.baseAddress!, count: line.count))
                }
            }
            mapView.addAnnotations(model.snapshot.markers.map(RouteAnnotation.init))
        }

        /// Bottom-right location button pressed: center on the phone's position
        /// without touching the zoom level.
        func applyCenterRequest(on mapView: MKMapView) {
            guard model.centerRequest != lastCenterRequest else { return }
            lastCenterRequest = model.centerRequest
            guard let origin = model.origin else { return }
            mapView.setCenter(origin, animated: true)
        }

        func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
            guard let line = overlay as? MKPolyline else { return MKOverlayRenderer(overlay: overlay) }
            let renderer = MKPolylineRenderer(polyline: line)
            renderer.strokeColor = UIColor(red: 0.10, green: 0.45, blue: 0.91, alpha: 0.9)
            renderer.lineWidth = 1
            renderer.lineCap = .round
            renderer.lineDashPattern = [14, 8]
            polylineRenderers[ObjectIdentifier(overlay)] = renderer
            return renderer
        }

        func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
            guard let route = annotation as? RouteAnnotation else { return nil }
            let id = "route-marker"
            let view = mapView.dequeueReusableAnnotationView(withIdentifier: id)
                ?? MKAnnotationView(annotation: annotation, reuseIdentifier: id)
            view.annotation = annotation
            let image = Self.markerImage(label: route.label)
            view.image = image
            // MapKit anchors the image's center. The destination dot is at
            // y=5, so move the center down to keep that dot on the coordinate.
            view.centerOffset = CGPoint(x: 0, y: image.size.height / 2 - 5)
            view.canShowCallout = false
            return view
        }

        /// Dot + always-visible label rendered into one image (callouts would
        /// hide the text until tapped, which is not what this map is for).
        /// The text sits on an opaque white pill so routes and basemap labels
        /// can't bleed through the glyphs.
        private static func markerImage(label: String) -> UIImage {
            let attributes: [NSAttributedString.Key: Any] = [
                .font: UIFont.systemFont(ofSize: 13, weight: .semibold),
                .foregroundColor: UIColor(red: 0.03, green: 0.20, blue: 0.44, alpha: 1),
            ]
            let text = NSAttributedString(string: label, attributes: attributes)
            let textSize = text.boundingRect(with: CGSize(width: 220, height: CGFloat.greatestFiniteMagnitude),
                                             options: .usesLineFragmentOrigin, context: nil).size
            let horizontalPadding: CGFloat = 8
            let verticalPadding: CGFloat = 3
            let size = CGSize(width: max(40, ceil(textSize.width) + horizontalPadding * 2),
                              height: ceil(textSize.height) + verticalPadding * 2 + 14)
            let format = UIGraphicsImageRendererFormat()
            format.scale = UIScreen.main.scale
            format.opaque = false
            return UIGraphicsImageRenderer(size: size, format: format).image { ctx in
                let dot = CGRect(x: size.width / 2 - 5, y: 0, width: 10, height: 10)
                ctx.cgContext.setFillColor(UIColor(red: 0.10, green: 0.45, blue: 0.91, alpha: 1).cgColor)
                ctx.cgContext.setStrokeColor(UIColor.white.cgColor)
                ctx.cgContext.setLineWidth(2)
                ctx.cgContext.fillEllipse(in: dot)
                ctx.cgContext.strokeEllipse(in: dot)
                let pill = CGRect(x: 0, y: 12, width: size.width,
                                  height: size.height - 12)
                UIColor.white.withAlphaComponent(0.92).setFill()
                UIBezierPath(roundedRect: pill, cornerRadius: pill.height / 2).fill()
                text.draw(with: CGRect(x: horizontalPadding, y: 12 + verticalPadding,
                                       width: size.width - horizontalPadding * 2,
                                       height: textSize.height),
                          options: .usesLineFragmentOrigin, context: nil)
            }
        }
    }
}
