package com.redsalmons.mobilewatchdog

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import com.redsalmons.mobilewatchdog.ui.App

class MainActivity : ComponentActivity() {
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) startCapture()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { App() }
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else startCapture()
    }

    private fun startCapture() {
        startService(Intent(this, CaptureVpnService::class.java))
    }
}
