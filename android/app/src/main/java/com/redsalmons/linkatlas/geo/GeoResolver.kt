package com.redsalmons.linkatlas.geo

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Locale

/** UI-side destination enrichment. Never part of the DPI flow model. */
enum class GeoField { COUNTRY, CITY, ASN }
enum class GeoStatus { HIT, MISS, UNAVAILABLE }

data class GeoRequest(
    val requestId: Long,
    val ipVersion: Int,
    val address: String,
    val fields: Set<GeoField>,
    val locale: String = GeoRequest.systemLocale,
) {
    companion object {
        val systemLocale: String
            get() = when (val language = Locale.getDefault().language) {
                // DB-IP uses these regional keys for Chinese and Portuguese.
                "zh" -> "zh-CN"
                "pt" -> "pt-BR"
                else -> language.ifEmpty { "en" }
            }
    }
}

data class GeoResult(
    val requestId: Long,
    val status: GeoStatus,
    val countryCode: String? = null,
    val countryName: String? = null,
    val region: String? = null,
    val city: String? = null,
    val latitude: Double? = null,
    val longitude: Double? = null,
    val asn: Long? = null,
    val org: String? = null,
    val source: String,
    val attribution: String,
    val approximate: Boolean = true,
)

interface GeoResolver {
    suspend fun resolve(requests: List<GeoRequest>): List<GeoResult>
}

class DbIpGeoResolver(
    private val context: Context,
    private val cityAsset: String = "geo/dbip-city-lite.mmdb",
    private val asnAsset: String = "geo/dbip-asn-lite.mmdb",
) : GeoResolver {
    companion object {
        const val ATTRIBUTION = "IP Geolocation by DB-IP · City names by GeoNames"
        const val SOURCE = "dbip_local"
    }

    private val lock = Any()
    private data class CacheEntry(val fields: Set<GeoField>, val locale: String, val result: GeoResult)
    private val cache = object : LinkedHashMap<String, CacheEntry>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CacheEntry>?) = size > 2048
    }
    private var cityReader = 0L
    private var asnReader = 0L

    override suspend fun resolve(requests: List<GeoRequest>): List<GeoResult> =
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                var hits = 0
                val results = requests.map { request ->
                    cache[request.address]?.takeIf {
                        it.fields == request.fields && it.locale == request.locale
                    }?.also { hits++ }?.result?.copy(requestId = request.requestId) ?:
                    runCatching { lookup(request) }.getOrElse {
                        GeoResult(request.requestId, GeoStatus.UNAVAILABLE,
                            source = SOURCE, attribution = ATTRIBUTION)
                    }.also { result ->
                        if (result.status != GeoStatus.UNAVAILABLE) {
                            cache[request.address] = CacheEntry(request.fields, request.locale, result)
                        }
                    }
                }
                if (android.util.Log.isLoggable("RouteMap", android.util.Log.DEBUG)) {
                    android.util.Log.d("RouteMap", "geo requests=${requests.size} cacheHits=$hits entries=${cache.size}")
                }
                results
            }
        }

    private fun lookup(request: GeoRequest): GeoResult {
        val wantsCity = request.fields.contains(GeoField.CITY) || request.fields.contains(GeoField.COUNTRY)
        val cityHandle = if (wantsCity) database(cityAsset, ::cityReader) { cityReader = it } else null
        val asnHandle = if (request.fields.contains(GeoField.ASN))
            database(asnAsset, ::asnReader) { asnReader = it } else null
        if ((wantsCity && cityHandle == null) || (request.fields.contains(GeoField.ASN) && asnHandle == null)) {
            return GeoResult(request.requestId, GeoStatus.UNAVAILABLE,
                source = SOURCE, attribution = ATTRIBUTION)
        }
        val cityMap = cityHandle?.let { NativeGeoDb.lookup(it, request.address, request.locale) }
        val asnMap = asnHandle?.let { NativeGeoDb.lookup(it, request.address, request.locale) }
        if (cityMap?.get("status") != "1" && asnMap?.get("status") != "1") {
            return GeoResult(request.requestId, GeoStatus.MISS, source = SOURCE, attribution = ATTRIBUTION)
        }
        return GeoResult(
            requestId = request.requestId,
            status = GeoStatus.HIT,
            countryCode = cityMap?.get("countryCode"),
            countryName = cityMap?.get("countryName"),
            region = cityMap?.get("region"),
            city = cityMap?.get("city"),
            latitude = cityMap?.get("latitude")?.toDoubleOrNull(),
            longitude = cityMap?.get("longitude")?.toDoubleOrNull(),
            asn = asnMap?.get("asn")?.toLongOrNull(),
            org = asnMap?.get("org"),
            source = SOURCE,
            attribution = ATTRIBUTION,
        )
    }

    fun close() = synchronized(lock) {
        cache.clear()
        if (cityReader != 0L) NativeGeoDb.close(cityReader)
        if (asnReader != 0L) NativeGeoDb.close(asnReader)
        cityReader = 0L
        asnReader = 0L
    }

    private fun database(asset: String, current: () -> Long, assign: (Long) -> Unit): Long? {
        current().takeIf { it != 0L }?.let { return it }
        val name = asset.substringAfterLast('/')
        val file = File(context.filesDir, "geo/$name")
        if (!file.exists()) {
            runCatching {
                context.assets.open(asset).use { input ->
                    file.parentFile?.mkdirs()
                    file.outputStream().use { input.copyTo(it) }
                }
            }.getOrElse { return null }
        }
        if (asset == cityAsset) {
            // Refresh the small name supplement on first open after each app
            // launch so installed updates do not leave an older translation file.
            runCatching {
                context.assets.open("city-names.tsv").use { input ->
                    File(file.parentFile, "city-names.tsv").outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
            }
        }
        return NativeGeoDb.open(file.absolutePath).takeIf { it != 0L }?.also(assign)
    }
}
