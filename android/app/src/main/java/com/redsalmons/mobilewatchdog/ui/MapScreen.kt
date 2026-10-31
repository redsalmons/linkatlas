package com.redsalmons.mobilewatchdog.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.os.Looper
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.suspendCancellableCoroutine
import org.maplibre.android.MapLibre
import org.maplibre.android.camera.CameraPosition
import org.maplibre.android.camera.CameraUpdateFactory
import org.maplibre.android.geometry.LatLng
import org.maplibre.android.location.LocationComponentActivationOptions
import org.maplibre.android.maps.MapLibreMap
import org.maplibre.android.maps.MapView
import org.maplibre.android.maps.Style
import kotlin.coroutines.resume

object MapConfig {
    // Placeholder style; replace with the production tile style URL.
    const val STYLE_URL = "https://demotiles.maplibre.org/style.json"
}

/** Starts on the whole world, then flies to the user's location once it is known. */
@Composable
fun MapScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val mapView = remember {
        MapLibre.getInstance(context)
        MapView(context).apply { onCreate(null) }
    }
    var map by remember { mutableStateOf<MapLibreMap?>(null) }
    var style by remember { mutableStateOf<Style?>(null) }
    var granted by remember { mutableStateOf(hasLocationPermission(context)) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        granted = it.values.any { ok -> ok }
    }

    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> mapView.onStart()
                Lifecycle.Event.ON_RESUME -> mapView.onResume()
                Lifecycle.Event.ON_PAUSE -> mapView.onPause()
                Lifecycle.Event.ON_STOP -> mapView.onStop()
                Lifecycle.Event.ON_DESTROY -> mapView.onDestroy()
                else -> {}
            }
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(Unit) {
        if (!granted) {
            permission.launch(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION))
        }
        mapView.getMapAsync { m ->
            m.cameraPosition = CameraPosition.Builder().target(LatLng(20.0, 0.0)).zoom(0.0).build()
            m.setStyle(MapConfig.STYLE_URL) { s ->
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
        m.animateCamera(CameraUpdateFactory.newLatLngZoom(LatLng(location.latitude, location.longitude), 15.0), 4000)
    }

    AndroidView(factory = { mapView }, modifier = modifier)
}

private fun hasLocationPermission(context: Context): Boolean =
    listOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION).any {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }

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
    val lm = context.getSystemService(LocationManager::class.java) ?: return null
    val provider = listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
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
