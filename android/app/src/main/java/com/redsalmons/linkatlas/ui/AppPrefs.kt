package com.redsalmons.linkatlas.ui

import android.content.Context
import com.redsalmons.linkatlas.ServiceWhitelist

/** Local-only preferences. Nothing here ever leaves the device. */
internal object AppPrefs {
    private const val FILE = "connection_atlas"
    private const val KEY_WHITELIST = "whitelist_v1"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun whitelist(context: Context): ServiceWhitelist =
        ServiceWhitelist.fromJson(prefs(context).getString(KEY_WHITELIST, "")!!)

    fun setWhitelist(context: Context, whitelist: ServiceWhitelist) {
        prefs(context).edit().putString(KEY_WHITELIST, whitelist.toJson()).apply()
    }
}
