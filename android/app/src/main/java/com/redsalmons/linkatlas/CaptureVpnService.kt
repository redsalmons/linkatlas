package com.redsalmons.linkatlas

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
            .setSession(getString(R.string.app_name))
            .setMtu(1500)
            .addAddress("10.8.0.2", 24)
            .addAddress("fd00::2", 64)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
        // Keep the DNS servers of the current *physical* network. When the active
        // network is itself a VPN (e.g. another tunnel app was connected), its
        // "DNS" is usually a private fake-ip resolver that is unreachable once we
        // take over — inheriting it leaves every app unable to resolve anything.
        val cm = getSystemService(ConnectivityManager::class.java)
        val dns = cm.allNetworks
            .filter {
                cm.getNetworkCapabilities(it)
                    ?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == false
            }
            .flatMap { cm.getLinkProperties(it)?.dnsServers ?: emptyList() }
            .filter {
                !it.isAnyLocalAddress && !it.isLoopbackAddress &&
                    !it.isLinkLocalAddress && !it.isSiteLocalAddress
            }
            .distinct()
            .ifEmpty {
                listOf(
                    java.net.InetAddress.getByName("223.5.5.5"),
                    java.net.InetAddress.getByName("1.1.1.1"),
                )
            }
        dns.forEach { runCatching { builder.addDnsServer(it) } }
        // Our own map download is not user traffic: keep this app outside its own
        // tunnel so those flows are never captured (and never listed).
        runCatching { builder.addDisallowedApplication(packageName) }
        val fd = builder.establish() ?: return
        val h = NativeTunnel.create(this)
        if (h == 0L) {
            fd.close()
            return
        }
        tun = fd
        handle = h
        CaptureStore.setHandle(h)
        NativeTunnel.start(h, fd.fd)
    }

    private fun stopCapture() {
        if (handle != 0L) {
            CaptureStore.destroy(handle)
            handle = 0L
        }
        tun?.close()
        tun = null
    }
}
