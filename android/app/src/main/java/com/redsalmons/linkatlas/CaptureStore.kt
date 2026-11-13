package com.redsalmons.linkatlas

/** Display fields copied from each active external flow; Geo data stays in the UI. */
data class DestinationObservation(val ip: String, val domain: String)

data class WebsiteVisit(
    val ip: String, val domain: String,
    val tcpConnections: Long, val udpFlows: Long,
    val bytesOut: Long, val bytesIn: Long,
    val protocol: Int, val fingerprint: String, val domainSource: Int,
)

/** Cross-thread handle to the capture session running in CaptureVpnService. */
object CaptureStore {
    @Volatile
    private var handle: Long = 0

    @Synchronized
    fun setHandle(value: Long) {
        handle = value
    }

    @Synchronized
    fun destroy(value: Long) {
        if (handle == value) handle = 0L
        NativeTunnel.destroy(value)
    }

    @Synchronized
    fun externalDestinations(): Array<DestinationObservation> {
        val value = handle
        return if (value != 0L) runCatching { NativeTunnel.externalDestinations(value) }
            .getOrDefault(emptyArray()) else emptyArray()
    }

    /** Bumped on every explicit clear; consumers poll it to tell a
     *  user-requested clear from a transient empty snapshot. */
    @Volatile var resetGeneration = 0
        private set

    /** Clears every record of the current session; the tunnel keeps forwarding. */
    @Synchronized
    fun clearRecords() {
        val value = handle
        if (value != 0L) runCatching { NativeTunnel.reset(value) }
        resetGeneration += 1
    }

    @Synchronized
    fun websiteVisits(): List<WebsiteVisit> =
        if (handle != 0L) runCatching { NativeTunnel.websiteVisits(handle).toList() }
            .getOrDefault(emptyList()) else emptyList()
}
