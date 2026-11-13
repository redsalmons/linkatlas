package com.redsalmons.linkatlas.geo

/** JNI wrapper for the shared libmaxminddb reader. */
object NativeGeoDb {
    init {
        System.loadLibrary("linkatlas")
    }

    external fun open(path: String): Long
    external fun lookup(handle: Long, address: String, locale: String): HashMap<String, String>
    external fun close(handle: Long)
}
