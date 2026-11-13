package com.redsalmons.linkatlas

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.WindowCompat
import com.redsalmons.linkatlas.ui.App

class MainActivity : ComponentActivity() {
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) startCapture()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // White surfaces: keep system bar icons dark so the clock stays readable.
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = true
            isAppearanceLightNavigationBars = true
        }
        setContent { App(onCaptureReady = ::ensureCapture) }
    }

    /** Called once the first-run explanation has been read, never before. */
    private fun ensureCapture() {
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else startCapture()
    }

    private fun startCapture() {
        startService(Intent(this, CaptureVpnService::class.java))
    }
}
