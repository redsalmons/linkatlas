package com.redsalmons.linkatlas.ui

import org.maplibre.android.geometry.LatLng
import org.maplibre.geojson.Feature
import org.maplibre.geojson.FeatureCollection
import org.maplibre.geojson.LineString
import org.maplibre.geojson.Point
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

data class RouteDestination(val ip: String, val label: String, val point: LatLng, val hasDomain: Boolean)
data class RouteGeometry(val lines: FeatureCollection, val markers: FeatureCollection)

object RouteArcs {
    fun build(origin: LatLng, destinations: List<RouteDestination>): RouteGeometry {
        val lines = mutableListOf<Feature>()
        val markers = mutableListOf<Feature>()
        destinations.forEach { destination ->
            val points = greatCircle(origin, destination.point)
            var segment = mutableListOf<Point>()
            var previous: LatLng? = null
            points.forEach { point ->
                if (previous != null && abs(point.longitude - previous!!.longitude) > 180.0) {
                    if (segment.size > 1) {
                        val line = Feature.fromGeometry(LineString.fromLngLats(segment))
                        line.addStringProperty("kind", "route")
                        lines += line
                    }
                    segment = mutableListOf()
                }
                segment += Point.fromLngLat(point.longitude, point.latitude)
                previous = point
            }
            if (segment.size > 1) {
                val line = Feature.fromGeometry(LineString.fromLngLats(segment))
                line.addStringProperty("kind", "route")
                lines += line
            }
            val bearing = bearing(points[max(0, points.lastIndex - 1)], points.last())
            val tip = Point.fromLngLat(destination.point.longitude, destination.point.latitude)
            val marker = Feature.fromGeometry(tip)
            marker.addStringProperty("title", destination.label)
            marker.addNumberProperty("labelPriority", if (destination.hasDomain) 0 else 1)
            marker.addNumberProperty("bearing", bearing)
            markers += marker
        }
        return RouteGeometry(FeatureCollection.fromFeatures(lines), FeatureCollection.fromFeatures(markers))
    }

    private fun greatCircle(start: LatLng, end: LatLng): List<LatLng> {
        val lat1 = Math.toRadians(start.latitude)
        val lon1 = Math.toRadians(start.longitude)
        val lat2 = Math.toRadians(end.latitude)
        val lon2 = Math.toRadians(end.longitude)
        val delta = 2 * kotlin.math.asin(sqrt(
            sin((lat2 - lat1) / 2).let { it * it } +
                cos(lat1) * cos(lat2) * sin((lon2 - lon1) / 2).let { it * it }
        ))
        if (delta < 0.0001) return listOf(start, end)
        val steps = min(96, max(16, (Math.toDegrees(delta) / 2).toInt()))
        // Bow perpendicular to the route direction like a flight-track arc, so
        // north-south routes curve sideways instead of overshooting latitude.
        // Lift vanishes at both ends: the line still lands on the endpoints.
        var dLon = Math.toDegrees(lon2 - lon1)
        if (dLon > 180) dLon -= 360 else if (dLon < -180) dLon += 360
        val dLat = Math.toDegrees(lat2 - lat1)
        val norm = max(0.001, sqrt(dLat * dLat + dLon * dLon))
        val perpLat = -dLon / norm
        val perpLon = dLat / norm
        val lift = min(5.0, Math.toDegrees(delta) * 0.03)
        return (0..steps).map { step ->
            val f = step.toDouble() / steps
            val a = sin((1 - f) * delta) / sin(delta)
            val b = sin(f * delta) / sin(delta)
            val x = a * cos(lat1) * cos(lon1) + b * cos(lat2) * cos(lon2)
            val y = a * cos(lat1) * sin(lon1) + b * cos(lat2) * sin(lon2)
            val z = a * sin(lat1) + b * sin(lat2)
            val k = lift * sin(Math.PI * f)
            val lat = Math.toDegrees(atan2(z, sqrt(x * x + y * y))) + k * perpLat
            val lon = Math.toDegrees(atan2(y, x)) + k * perpLon
            LatLng(min(85.0, max(-85.0, lat)), lon)
        }
    }

    private fun bearing(start: LatLng, end: LatLng): Double {
        val lat1 = Math.toRadians(start.latitude)
        val lat2 = Math.toRadians(end.latitude)
        val deltaLon = Math.toRadians(end.longitude - start.longitude)
        val y = sin(deltaLon) * cos(lat2)
        val x = cos(lat1) * sin(lat2) - sin(lat1) * cos(lat2) * cos(deltaLon)
        return (Math.toDegrees(atan2(y, x)) + 360.0) % 360.0
    }
}
