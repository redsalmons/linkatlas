package com.redsalmons.linkatlas.ui

import com.redsalmons.linkatlas.BuildConfig

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color as AndroidColor
import android.graphics.Paint
import android.graphics.Path
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.os.Looper
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.redsalmons.linkatlas.CaptureStore
import com.redsalmons.linkatlas.R
import com.redsalmons.linkatlas.geo.DbIpGeoResolver
import com.redsalmons.linkatlas.geo.GeoField
import com.redsalmons.linkatlas.geo.GeoRequest
import com.redsalmons.linkatlas.geo.GeoStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.maplibre.android.MapLibre
import org.maplibre.android.camera.CameraPosition
import org.maplibre.android.camera.CameraUpdateFactory
import org.maplibre.android.geometry.LatLng
import org.maplibre.android.location.LocationComponentActivationOptions
import org.maplibre.android.maps.MapLibreMap
import org.maplibre.android.maps.MapView
import org.maplibre.android.maps.Style
import org.maplibre.android.style.expressions.Expression
import org.maplibre.android.style.layers.CircleLayer
import org.maplibre.android.style.layers.LineLayer
import org.maplibre.android.style.layers.Property
import org.maplibre.android.style.layers.PropertyFactory.circleColor
import org.maplibre.android.style.layers.PropertyFactory.circleRadius
import org.maplibre.android.style.layers.PropertyFactory.circleStrokeColor
import org.maplibre.android.style.layers.PropertyFactory.circleStrokeWidth
import org.maplibre.android.style.layers.PropertyFactory.iconAllowOverlap
import org.maplibre.android.style.layers.PropertyFactory.iconAnchor
import org.maplibre.android.style.layers.PropertyFactory.iconIgnorePlacement
import org.maplibre.android.style.layers.PropertyFactory.iconImage
import org.maplibre.android.style.layers.PropertyFactory.iconRotate
import org.maplibre.android.style.layers.PropertyFactory.iconRotationAlignment
import org.maplibre.android.style.layers.PropertyFactory.iconSize
import org.maplibre.android.style.layers.PropertyFactory.lineBlur
import org.maplibre.android.style.layers.PropertyFactory.lineCap
import org.maplibre.android.style.layers.PropertyFactory.lineColor
import org.maplibre.android.style.layers.PropertyFactory.lineDasharray
import org.maplibre.android.style.layers.PropertyFactory.lineJoin
import org.maplibre.android.style.layers.PropertyFactory.lineOpacity
import org.maplibre.android.style.layers.PropertyFactory.lineWidth
import org.maplibre.android.style.layers.PropertyFactory.textAllowOverlap
import org.maplibre.android.style.layers.PropertyFactory.textAnchor
import org.maplibre.android.style.layers.PropertyFactory.textColor
import org.maplibre.android.style.layers.PropertyFactory.textField
import org.maplibre.android.style.layers.PropertyFactory.textFont
import org.maplibre.android.style.layers.PropertyFactory.textHaloColor
import org.maplibre.android.style.layers.PropertyFactory.textHaloWidth
import org.maplibre.android.style.layers.PropertyFactory.textIgnorePlacement
import org.maplibre.android.style.layers.PropertyFactory.textJustify
import org.maplibre.android.style.layers.PropertyFactory.textOffset
import org.maplibre.android.style.layers.PropertyFactory.textSize
import org.maplibre.android.style.layers.PropertyFactory.symbolSortKey
import org.maplibre.android.style.layers.SymbolLayer
import org.maplibre.android.style.sources.GeoJsonSource
import org.maplibre.geojson.FeatureCollection
import kotlin.coroutines.resume
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.sin

object MapConfig {
    // Placeholder style; replace with the production tile style URL.
    const val STYLE_URL = "https://tiles.openfreemap.org/styles/liberty"
    const val ROUTE_SOURCE = "linkatlas-routes"
    const val MARKER_SOURCE = "linkatlas-route-markers"
    const val ARROW_IMAGE = "linkatlas-route-arrow"
}

/** Shows active public destinations as arcing, arrow-headed routes from the user's location. */
@Composable
fun MapScreen(modifier: Modifier = Modifier, recenterTick: Int = 0, onBack: () -> Unit = {}) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val mapView = remember {
        MapLibre.getInstance(context)
        MapView(context).apply { onCreate(null) }
    }
    val resolver = remember { DbIpGeoResolver(context.applicationContext) }
    var map by remember { mutableStateOf<MapLibreMap?>(null) }
    var style by remember { mutableStateOf<Style?>(null) }
    var granted by remember { mutableStateOf(hasLocationPermission(context)) }
    var ask by remember { mutableStateOf(false) }
    var userLocation by remember { mutableStateOf<LatLng?>(null) }
    val denyAndBack = {
        Toast.makeText(context, R.string.map_location_toast, Toast.LENGTH_LONG).show()
        onBack()
    }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { results ->
        val ok = results.values.any { it }
        granted = ok
        if (!ok) denyAndBack()
    }

    DisposableEffect(resolver) {
        onDispose { resolver.close() }
    }

    if (ask) {
        AlertDialog(
            onDismissRequest = {},
            title = { Text(stringResource(R.string.map_location_title)) },
            text = { Text(stringResource(R.string.map_location_body)) },
            confirmButton = {
                TextButton(onClick = {
                    ask = false
                    permission.launch(arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION))
                }) { Text(stringResource(R.string.map_location_allow)) }
            },
            dismissButton = {
                TextButton(onClick = denyAndBack) { Text(stringResource(R.string.map_location_deny)) }
            },
        )
    }

    DisposableEffect(lifecycle) {
        var destroyed = false
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> mapView.onStart()
                Lifecycle.Event.ON_RESUME -> mapView.onResume()
                Lifecycle.Event.ON_PAUSE -> mapView.onPause()
                Lifecycle.Event.ON_STOP -> mapView.onStop()
                Lifecycle.Event.ON_DESTROY -> {
                    mapView.onDestroy()
                    destroyed = true
                }
                else -> {}
            }
        }
        lifecycle.addObserver(observer)
        onDispose {
            lifecycle.removeObserver(observer)
            if (!destroyed) {
                mapView.onPause()
                mapView.onStop()
                mapView.onDestroy()
            }
        }
    }

    LaunchedEffect(Unit) {
        if (!granted) ask = true
        mapView.getMapAsync { m ->
            m.cameraPosition = CameraPosition.Builder().target(LatLng(20.0, 0.0)).zoom(0.0).build()
            m.setStyle(MapConfig.STYLE_URL) { s ->
                installRouteLayers(s)
                map = m
                style = s
            }
        }
    }

    LaunchedEffect(map, style, granted) {
        val m = map ?: return@LaunchedEffect
        val s = style ?: return@LaunchedEffect
        if (!granted) return@LaunchedEffect
        showUserLocation(context, m, s)
        val location = currentLocation(context) ?: return@LaunchedEffect
        userLocation = LatLng(location.latitude, location.longitude)
        m.moveCamera(
            CameraUpdateFactory.newCameraPosition(
                CameraPosition.Builder()
                    .target(userLocation!!)
                    .zoom(4.0)
                    .tilt(0.0)
                    .build()
            )
        )
    }

    LaunchedEffect(map, style, granted) {
        val currentStyle = style ?: return@LaunchedEffect
        val currentMap = map ?: return@LaunchedEffect
        if (!granted) return@LaunchedEffect
        var requestId = 1L
        var lastOrigin: Pair<Long, Long>? = null
        // Traffic records accumulate until the app exits or the user clears
        // them: a destination once observed stays on the map even after its
        // flows close.
        val chosenNames = mutableMapOf<String, String>()
        val nameUsedByIp = mutableMapOf<String, String>()
        val destinationsByIp = mutableMapOf<String, RouteDestination>()
        var lastReset = CaptureStore.resetGeneration
        while (isActive) {
            // The location component is only activated once permission is granted;
            // asking it earlier throws. Keep polling so a late fix still starts the
            // routes — the one-shot lookup above may legitimately return null.
            val fix = runCatching { currentMap.locationComponent.lastKnownLocation }.getOrNull()
            var origin = fix?.let { LatLng(it.latitude, it.longitude) } ?: userLocation
            if (origin == null) {
                // The one-shot lookup above can run before any provider has a fix;
                // retry here so a late location still starts the routes.
                currentLocation(context)?.let {
                    userLocation = LatLng(it.latitude, it.longitude)
                    origin = userLocation
                }
            }
            if (origin == null) {
                if (BuildConfig.DEBUG)
                    android.util.Log.d("RouteMap", "tick: no origin yet (fix=${fix != null})")
                delay(3000)
                continue
            }
            if (CaptureStore.resetGeneration != lastReset) {
                lastReset = CaptureStore.resetGeneration
                chosenNames.clear()
                nameUsedByIp.clear()
                destinationsByIp.clear()
                lastOrigin = null
            }
            // IP is the primary key. Multiple flows may share an IP; keep the
            // first stable observed name once seen.
            withContext(Dispatchers.Default) {
                CaptureStore.externalDestinations().groupBy { it.ip }
            }.forEach { (ip, flows) ->
                val name = flows.map { it.domain.trim().lowercase(java.util.Locale.ROOT) }
                    .filter { it.isNotEmpty() }.minOrNull().orEmpty()
                val old = chosenNames[ip]
                if (old == null || (old.isEmpty() && name.isNotEmpty())) chosenNames[ip] = name
            }
            val originKey = Math.round(origin.latitude * 10000) to Math.round(origin.longitude * 10000)
            val pending = chosenNames.keys.filter { nameUsedByIp[it] != chosenNames[it] }.sorted()
            var dirty = false
            if (pending.isNotEmpty()) {
                val locale = GeoRequest.systemLocale
                val requests = pending.map {
                    GeoRequest(requestId++, ipVersion = if (it.contains(':')) 6 else 4,
                        address = it, fields = setOf(GeoField.CITY, GeoField.COUNTRY), locale = locale)
                }
                val requestById = requests.associateBy { it.requestId }
                for (result in resolver.resolve(requests)) {
                    val ip = requestById[result.requestId]?.address ?: continue
                    if (result.status == GeoStatus.UNAVAILABLE) continue
                    val name = chosenNames[ip] ?: continue
                    nameUsedByIp[ip] = name
                    val latitude = result.latitude ?: continue
                    val longitude = result.longitude ?: continue
                    if (result.status != GeoStatus.HIT) continue
                    val title = name.ifEmpty { ip }
                    val geo = result.city ?: result.countryName.orEmpty()
                    val label = if (geo.isEmpty()) title else "$geo($title)"
                    destinationsByIp[ip] = RouteDestination(ip = ip,
                        label = label.ifEmpty { "Unknown" },
                        point = LatLng(latitude, longitude), hasDomain = name.isNotEmpty())
                    dirty = true
                }
            }
            if (dirty || originKey != lastOrigin) {
                lastOrigin = originKey
                // IPs geolocating to the same city coordinate would draw
                // identical, perfectly overlapping arcs — fan them out slightly
                // so each destination keeps its own visible line and label.
                val routes = destinationsByIp.values.sortedBy { it.ip }
                fun cell(p: LatLng) = Math.round(p.latitude * 4) to Math.round(p.longitude * 4)
                val groups = routes.mapIndexed { i, d -> cell(d.point) to i }
                    .groupBy({ it.first }, { it.second })
                val fanned = routes.mapIndexed { i, d ->
                    val siblings = groups[cell(d.point)] ?: listOf(i)
                    val order = siblings.indexOf(i)
                    if (siblings.size <= 1 || order <= 0) d else {
                        val angle = 2 * Math.PI * order / siblings.size
                        d.copy(point = LatLng(
                            (d.point.latitude + 0.35 * sin(angle)).coerceIn(-85.0, 85.0),
                            d.point.longitude + 0.35 * cos(angle) /
                                max(0.2, cos(Math.toRadians(d.point.latitude)))))
                    }
                }
                val geometry = RouteArcs.build(origin, fanned)
                currentStyle.getSourceAs<GeoJsonSource>(MapConfig.ROUTE_SOURCE)?.setGeoJson(geometry.lines)
                // SDK 13.7.1's object/JNI path dropped Point features on the device.
                // Standard GeoJSON text preserves the points and their properties.
                currentStyle.getSourceAs<GeoJsonSource>(MapConfig.MARKER_SOURCE)?.setGeoJson(geometry.markers.toJson())
                if (BuildConfig.DEBUG)
                    android.util.Log.d("RouteMap", "render routes=${fanned.size}")
            }
            delay(3000)
        }
    }

    LaunchedEffect(recenterTick) {
        if (recenterTick <= 0) return@LaunchedEffect
        userLocation?.let { map?.animateCamera(CameraUpdateFactory.newLatLng(it), 600) }
    }

    // Marching-dash flow animation: an odd-length dash array shifts phase as the
    // run lengths swap each tick, so dashes walk outward along each route.
    LaunchedEffect(style) {
        val currentStyle = style ?: return@LaunchedEffect
        val dash = 14f
        val gap = 8f
        val step = 4f
        val frames = buildList<Array<Float>> {
            var i = 0f
            while (i < dash) { add(arrayOf(i, gap, dash - i)); i += step }
            var q = step
            while (q <= gap) { add(arrayOf(0f, q, dash, gap - q)); q += step }
        }.toTypedArray()
        var frame = 0
        while (isActive) {
            currentStyle.getLayerAs<LineLayer>("linkatlas-route-line")
                ?.setProperties(lineDasharray(frames[frame]))
            frame = (frame + 1) % frames.size
            delay(60)
        }
    }

    AndroidView(factory = { mapView }, modifier = modifier)
}

private fun installRouteLayers(style: Style) {
    style.addImage(MapConfig.ARROW_IMAGE, arrowBitmap())
    style.addSource(GeoJsonSource(MapConfig.ROUTE_SOURCE, FeatureCollection.fromFeatures(emptyList())))
    style.addSource(GeoJsonSource(MapConfig.MARKER_SOURCE, FeatureCollection.fromFeatures(emptyList())))
    style.addLayer(LineLayer("linkatlas-route-glow", MapConfig.ROUTE_SOURCE).withProperties(
        lineColor("#0B4EA2"), lineWidth(9f), lineBlur(7f), lineOpacity(0.28f),
        lineCap(Property.LINE_CAP_ROUND), lineJoin(Property.LINE_JOIN_ROUND)
    ))
    style.addLayer(LineLayer("linkatlas-route-line", MapConfig.ROUTE_SOURCE).withProperties(
        lineColor("#1A73E8"), lineWidth(1f), lineOpacity(0.95f),
        lineCap(Property.LINE_CAP_ROUND), lineJoin(Property.LINE_JOIN_ROUND)
    ).withFilter(Expression.eq(Expression.get("kind"), "route")))
    style.addLayer(CircleLayer("linkatlas-route-dot", MapConfig.MARKER_SOURCE).withProperties(
        circleRadius(5f), circleColor("#1A73E8"), circleStrokeWidth(2f), circleStrokeColor("#FFFFFF")
    ))
    style.addLayer(SymbolLayer("linkatlas-route-arrow", MapConfig.MARKER_SOURCE).withProperties(
        iconImage(MapConfig.ARROW_IMAGE), iconRotate(Expression.get("bearing")),
        iconSize(0.55f), iconAnchor(Property.ICON_ANCHOR_CENTER),
        iconRotationAlignment(Property.ICON_ROTATION_ALIGNMENT_MAP),
        iconAllowOverlap(true), iconIgnorePlacement(true)
    ))
    style.addLayer(SymbolLayer("linkatlas-route-label", MapConfig.MARKER_SOURCE).withProperties(
        symbolSortKey(Expression.get("labelPriority")),
        textField(Expression.get("title")), textFont(arrayOf("Noto Sans Regular")),
        textSize(13f), textAnchor(Property.TEXT_ANCHOR_BOTTOM),
        textJustify(Property.TEXT_JUSTIFY_CENTER), textColor("#08336F"),
        textHaloColor("#FFFFFF"), textHaloWidth(2f),
        textOffset(arrayOf(0f, -1.6f)), textAllowOverlap(false), textIgnorePlacement(false)
    ))
}

private fun arrowBitmap(): Bitmap {
    val size = 96
    val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(bitmap)
    canvas.drawPath(Path().apply {
        moveTo(48f, 4f); lineTo(84f, 88f); lineTo(48f, 70f); lineTo(12f, 88f); close()
    }, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = AndroidColor.WHITE })
    canvas.drawPath(Path().apply {
        moveTo(48f, 16f); lineTo(72f, 78f); lineTo(48f, 64f); lineTo(24f, 78f); close()
    }, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = AndroidColor.parseColor("#1A73E8") })
    return bitmap
}

private fun hasLocationPermission(context: Context): Boolean =
    ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) ==
        PackageManager.PERMISSION_GRANTED

@SuppressLint("MissingPermission")
private fun showUserLocation(context: Context, map: MapLibreMap, style: Style) {
    map.locationComponent.apply {
        activateLocationComponent(LocationComponentActivationOptions.builder(context, style).build())
        isLocationComponentEnabled = true
    }
}

@Suppress("DEPRECATION")
@SuppressLint("MissingPermission")
private suspend fun currentLocation(context: Context): Location? {
    if (!hasLocationPermission(context)) return null
    val lm = context.getSystemService(LocationManager::class.java) ?: return null
    // Coarse permission only: the network provider is the one that can answer.
    val provider = listOf(LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER)
        .firstOrNull { lm.isProviderEnabled(it) } ?: return null
    return suspendCancellableCoroutine { cont ->
        if (Build.VERSION.SDK_INT >= 30) {
            lm.getCurrentLocation(provider, null, ContextCompat.getMainExecutor(context)) { location ->
                if (cont.isActive) cont.resume(location ?: lm.getLastKnownLocation(provider))
            }
        } else {
            lm.requestSingleUpdate(provider, { location -> if (cont.isActive) cont.resume(location) }, Looper.getMainLooper())
        }
    }
}
