package com.redsalmons.linkatlas

import android.net.VpnService

/** JNI bindings to the shared C core (app/src/main/cpp/linkatlas_jni.cpp). */
object NativeTunnel {
    init {
        System.loadLibrary("linkatlas")
    }

    external fun create(service: VpnService): Long
    external fun start(handle: Long, tunFd: Int)
    external fun destroy(handle: Long)
    /** Drops the session's retained flows without interrupting the tunnel. */
    external fun reset(handle: Long)
    /** Full active public destination snapshot, including observed SNI / HTTP Host. */
    external fun externalDestinations(handle: Long): Array<DestinationObservation>
    external fun websiteVisits(handle: Long): Array<WebsiteVisit>
}
