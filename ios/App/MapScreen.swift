import CoreLocation
import MapLibre
import SwiftUI

enum MapConfig {
    // Placeholder style; replace with the production tile style URL.
    static let styleURL = URL(string: "https://tiles.openfreemap.org/styles/liberty")!
}

/// Starts on the whole world, then flies to the user's location once it is known.
struct MapScreen: UIViewRepresentable {
    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> MLNMapView {
        let map = MLNMapView(frame: .zero, styleURL: MapConfig.styleURL)
        map.delegate = context.coordinator
        map.setCenter(CLLocationCoordinate2D(latitude: 20, longitude: 0), zoomLevel: 0, animated: false)
        map.showsUserLocation = true
        return map
    }

    func updateUIView(_ uiView: MLNMapView, context: Context) {}

    final class Coordinator: NSObject, MLNMapViewDelegate {
        private var didFly = false

        func mapView(_ mapView: MLNMapView, didUpdate userLocation: MLNUserLocation?) {
            guard !didFly, let coordinate = userLocation?.location?.coordinate,
                  CLLocationCoordinate2DIsValid(coordinate) else { return }
            didFly = true
            // Same final zoom level (15) as Android.
            let altitude = MLNAltitudeForZoomLevel(15, 0, coordinate.latitude, mapView.bounds.size)
            let camera = MLNMapCamera(lookingAtCenter: coordinate, altitude: altitude, pitch: 0, heading: 0)
            mapView.fly(to: camera, withDuration: 4, completionHandler: nil)
        }
    }
}
