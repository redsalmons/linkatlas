package com.redsalmons.mobilewatchdog

import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor

/** Routes all traffic into the tunnel; the C core forwards it unchanged. */
class CaptureVpnService : VpnService() {
    private var handle = 0L
    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startCapture()
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        stopCapture()
        stopSelf()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    private fun startCapture() {
        if (handle != 0L) return
        val builder = Builder()
            .setSession("Mobile Watchdog")
            .setMtu(1500)
            .addAddress("10.8.0.2", 24)
            .addAddress("fd00::2", 64)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
        // Keep the DNS servers of the current network.
        val cm = getSystemService(ConnectivityManager::class.java)
        cm.activeNetwork?.let { cm.getLinkProperties(it) }?.dnsServers?.forEach {
            runCatching { builder.addDnsServer(it) }
        }
        val fd = builder.establish() ?: return
        val h = NativeTunnel.create(this)
        if (h == 0L) {
            fd.close()
            return
        }
        tun = fd
        handle = h
        NativeTunnel.start(h, fd.fd)
    }

    private fun stopCapture() {
        if (handle != 0L) {
            NativeTunnel.destroy(handle)
            handle = 0L
        }
        tun?.close()
        tun = null
    }
}
