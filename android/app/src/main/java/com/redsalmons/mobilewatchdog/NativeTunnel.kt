package com.redsalmons.mobilewatchdog

import android.net.VpnService

/** JNI bindings to the shared C core (app/src/main/cpp/watchdog_jni.cpp). */
object NativeTunnel {
    init {
        System.loadLibrary("watchdog")
    }

    external fun create(service: VpnService): Long
    external fun start(handle: Long, tunFd: Int)
    external fun destroy(handle: Long)
}
