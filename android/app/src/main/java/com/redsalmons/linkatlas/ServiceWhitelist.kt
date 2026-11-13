package com.redsalmons.linkatlas

import com.redsalmons.linkatlas.ui.WebsiteStat
import org.json.JSONArray
import org.json.JSONObject

/** Server-provided list of destinations hidden from every screen. */
data class ServiceWhitelist(val domains: List<String> = emptyList(), val ips: List<String> = emptyList()) {

    val empty: Boolean get() = domains.isEmpty() && ips.isEmpty()

    internal fun matches(website: WebsiteStat): Boolean {
        if (website.domain.isNotEmpty() && domains.any { domainMatches(it, website.domain) }) return true
        return website.ips.isNotEmpty() && website.ips.all { ip -> ips.any { ipMatches(it, ip) } }
    }

    // "a.b.c.*" is a /24 prefix match; anything else must match exactly.
    private fun ipMatches(pattern: String, ip: String): Boolean =
        if (pattern.endsWith(".*")) ip.startsWith(pattern.dropLast(1)) else ip == pattern

    // "*" matches one or more labels including deeper subdomains; a leading
    // "*." also matches the bare remainder (e.g. "*.youtube.com" hits youtube.com).
    private fun domainMatches(pattern: String, domain: String): Boolean {
        if (!pattern.contains('*')) return domain == pattern || domain.endsWith(".$pattern")
        val body = pattern.split('.').joinToString("\\.") {
            if (it == "*") ".+" else Regex.escape(it)
        }
        if (Regex("^$body$").matches(domain)) return true
        return pattern.startsWith("*.") && domainMatches(pattern.substring(2), domain)
    }

    fun toJson(): String = JSONObject()
        .put("domains", JSONArray(domains)).put("ips", JSONArray(ips)).toString()

    companion object {
        val EMPTY = ServiceWhitelist()

        fun fromJson(raw: String): ServiceWhitelist = runCatching {
            val json = JSONObject(raw)
            fun list(key: String) = json.optJSONArray(key)?.let { arr ->
                (0 until arr.length()).map { arr.getString(it).lowercase() }
            }.orEmpty()
            ServiceWhitelist(list("domains"), list("ips"))
        }.getOrDefault(EMPTY)
    }
}
