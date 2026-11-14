package com.redsalmons.linkatlas.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.redsalmons.linkatlas.*
import com.redsalmons.linkatlas.R
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.net.InetAddress
import java.util.Locale
import java.util.UUID

internal fun WebsiteStat.snapshot(): String = JSONObject().put("title", title)
    .put("domain", domain).put("ips", JSONArray(ips)).put("tcp", tcp).put("udp", udp)
    .put("bytes_out", bytesOut).put("bytes_in", bytesIn).put("request_id", UUID.randomUUID().toString()).toString()

private fun Context.activity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.activity()
    else -> null
}

private fun publicIP(raw: String): Boolean = runCatching {
    require(raw.contains(':') || raw.matches(Regex("\\d+\\.\\d+\\.\\d+\\.\\d+")))
    val ip = InetAddress.getByName(raw)
    if (ip.isAnyLocalAddress || ip.isLoopbackAddress || ip.isLinkLocalAddress ||
        ip.isSiteLocalAddress || ip.isMulticastAddress) return false
    val b = ip.address.map { it.toInt() and 255 }
    fun publicV4(v: List<Int>) = !(v[0] == 0 || v[0] >= 224 || v[0] == 127 || v[0] == 10 ||
        (v[0] == 100 && v[1] in 64..127) || (v[0] == 192 && v[1] == 0) ||
        (v[0] == 198 && (v[1] in 18..19 || (v[1] == 51 && v[2] == 100))) ||
        (v[0] == 203 && v[1] == 0 && v[2] == 113))
    if (b.size == 4) return publicV4(b)
    if (b.size != 16) return false
    if (b.take(10).all { it == 0 } && b[10] == 0xff && b[11] == 0xff)
        return publicV4(b.takeLast(4))
    // Keep in sync with the server's publicAddress: 2000::/3 global unicast,
    // excluding Teredo (2001::/32), 6to4 (2002::/16) and documentation ranges.
    if (b[0] !in 0x20..0x3f) return false
    if (b[0] == 0x20 && b[1] == 0x01 &&
        ((b[2] == 0x00 && b[3] == 0x00) || (b[2] == 0x0d && b[3] == 0xb8))) return false
    if (b[0] == 0x20 && b[1] == 0x02) return false
    true
}.getOrDefault(false)

@Composable
internal fun LookupDetailScreen(snapshot: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val selected = remember(snapshot) { JSONObject(snapshot) }
    val scope = rememberCoroutineScope()
    val api = remember { runCatching { LookupServiceClient.configured(context) }.getOrNull() }
    val billing = remember { runCatching { LookupBilling.configured(context) }.getOrNull() }
    val prefs = remember { context.getSharedPreferences("lookup", Context.MODE_PRIVATE) }
    var consent by remember { mutableStateOf(prefs.getBoolean("consent", false)) }
    var state by rememberSaveable(snapshot) { mutableStateOf(if (consent) "loading" else "idle") }
    var result by rememberSaveable(snapshot) { mutableStateOf("") }
    var checkout by remember { mutableStateOf(false) }
    var waitingForPurchase by rememberSaveable(snapshot) { mutableStateOf(false) }
    var lastCredit by rememberSaveable(snapshot) { mutableLongStateOf(billing?.update?.value?.sequence ?: 0) }
    val purchase by (billing?.update ?: remember { kotlinx.coroutines.flow.MutableStateFlow(LookupBilling.Update()) }).collectAsState()
    val products by (billing?.products ?: remember { kotlinx.coroutines.flow.MutableStateFlow(emptyMap<String, com.android.billingclient.api.ProductDetails>()) }).collectAsState()

    suspend fun query() {
        if (api == null) { state = "unavailable"; return }
        state = "loading"
        try {
            val domain = IDN.toASCII(selected.optString("domain").trimEnd('.')).lowercase(Locale.ROOT)
            val privateDomain = listOf(".local", ".localhost", ".internal", ".home.arpa", ".invalid", ".test").any { domain.endsWith(it) }
            val ips = selected.getJSONArray("ips")
            // One target per lookup: a named service queries its domain only;
            // an IP-only entry queries its single public address.
            val public = if (domain.isEmpty())
                (0 until ips.length()).map { ips.getString(it) }.filter(::publicIP).take(1)
                else emptyList()
            if (privateDomain || (domain.isEmpty() && public.isEmpty())) { state = "private"; return }
            val body = JSONObject().put("request_id", selected.getString("request_id"))
                .put("query", JSONObject().put("domain", domain).put("ips", JSONArray(public)))
                .put("lang", if (Locale.getDefault().language == "zh") "zh" else "en").put("schema", 3)
            val response = api.request("/v1/lookupaddress/lookup", body)
            result = response.getJSONObject("result").toString()
            state = "done"
        } catch (error: LookupServiceClient.ApiError) {
            state = when {
                error.code == 1003 -> "purchase"
                error.code == 1007 || error.code == 1011 -> "busy"
                error.code == 1013 -> "expired_request"
                error.code == 1001 -> "private"
                else -> "unavailable"
            }
        } catch (_: Exception) { state = "unavailable" }
    }

    LaunchedEffect(consent) {
        if (!consent) return@LaunchedEffect
        try {
            val config = api?.request("/v1/lookupaddress/config", JSONObject().put("schema", 3))
            checkout = config?.optBoolean("purchases_enabled") == true && config.optBoolean("store_ready")
            if (checkout) billing?.loadProducts()
            billing?.restore()
        } catch (_: Exception) { checkout = false }
        if (state != "done") query()
    }
    LaunchedEffect(purchase) {
        if (purchase.state == "credited" && purchase.sequence != lastCredit) {
            lastCredit = purchase.sequence
            if (waitingForPurchase) { waitingForPurchase = false; query() }
        }
        if (purchase.state == "cancelled") waitingForPurchase = false
    }

    Column(Modifier.fillMaxSize().background(Color(0xFFF4F6FA)).safeDrawingPadding()) {
        SettingsHeader(stringResource(R.string.lookup_title), onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(selected.getString("title"), style = MaterialTheme.typography.titleLarge)
            Text((0 until selected.getJSONArray("ips").length()).joinToString("\n") { selected.getJSONArray("ips").getString(it) })
            Text(stringResource(R.string.website_connections, selected.getLong("tcp"), selected.getLong("udp")))
            Text(stringResource(R.string.traffic_out_in, formatBytes(selected.getLong("bytes_out")), formatBytes(selected.getLong("bytes_in"))))
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.lookup_analysis), style = MaterialTheme.typography.titleMedium)
                    if (!consent) {
                        Text(stringResource(R.string.lookup_consent))
                        Button(onClick = { prefs.edit().putBoolean("consent", true).apply(); consent = true }) {
                            Text(stringResource(R.string.lookup_continue))
                        }
                    } else {
                        when (state) {
                            "loading" -> { CircularProgressIndicator(); Text(stringResource(R.string.lookup_loading)) }
                            "done" -> LookupResultView(result, selected)
                            "private" -> Text(stringResource(R.string.lookup_private))
                            "busy" -> Text(stringResource(R.string.lookup_busy))
                            "expired_request" -> Text(stringResource(R.string.lookup_request_expired))
                            "purchase" -> Text(stringResource(R.string.lookup_purchase_needed))
                            else -> Text(stringResource(R.string.lookup_unavailable))
                        }
                        if (state == "purchase") {
                            val processing = purchase.state in listOf("paying", "verifying", "pending")
                            if (!checkout) Text(stringResource(R.string.lookup_checkout_disabled))
                            if (purchase.state in listOf("paying", "verifying", "pending", "failed", "expired")) {
                                Text(stringResource(when (purchase.state) {
                                    "paying" -> R.string.lookup_paying
                                    "verifying" -> R.string.lookup_verifying
                                    "pending" -> R.string.lookup_pending
                                    "expired" -> R.string.lookup_expired
                                    else -> R.string.lookup_verify_failed
                                }))
                            }
                            for (id in listOf(LookupBilling.SINGLE, LookupBilling.PRO, LookupBilling.PRO_YEAR)) {
                                val price = if (BuildConfig.LOOKUP_DEVELOPMENT) null
                                    else if (products.containsKey(id)) billing?.price(id) else null
                                Button(modifier = Modifier.fillMaxWidth(),
                                    enabled = checkout && (BuildConfig.LOOKUP_DEVELOPMENT || price != null)
                                        && !processing && !waitingForPurchase,
                                    onClick = { context.activity()?.let { waitingForPurchase = true; billing?.buy(it, id) } }) {
                                    Text(stringResource(when (id) {
                                        LookupBilling.SINGLE -> R.string.lookup_single
                                        LookupBilling.PRO -> R.string.lookup_pro
                                        else -> R.string.lookup_pro_year
                                    }) + (price?.let { " · $it" } ?: ""))
                                }
                            }
                            Text(stringResource(R.string.lookup_subscription_note), style = MaterialTheme.typography.bodySmall)
                            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                TextButton(onClick = {
                                    context.startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW,
                                        android.net.Uri.parse("https://redsalmons.github.io/linkatlas/terms.html")))
                                }) { Text(stringResource(R.string.lookup_terms), style = MaterialTheme.typography.bodySmall) }
                                TextButton(onClick = {
                                    context.startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW,
                                        android.net.Uri.parse("https://redsalmons.github.io/linkatlas/privacy.html")))
                                }) { Text(stringResource(R.string.lookup_privacy_short), style = MaterialTheme.typography.bodySmall) }
                            }
                            if (api != null) {
                                TextButton(enabled = purchase.state !in listOf("paying", "verifying"),
                                    onClick = { billing?.restore() }) { Text(stringResource(R.string.lookup_restore)) }
                            }
                        }
                        if (state !in listOf("loading", "done", "private", "expired_request")) {
                            TextButton(onClick = { scope.launch { query() } }) { Text(stringResource(R.string.lookup_retry)) }
                        }
                    }
                }
            }
        }
    }
}

private data class InsightGroup(val title: String, val lines: List<String>)

@Composable
private fun LookupResultView(resultJson: String, selected: JSONObject) {
    val result = remember(resultJson) { runCatching { JSONObject(resultJson) }.getOrNull() }
    val domain = selected.optString("domain")
    val ips = selected.optJSONArray("ips")
    val target = buildString {
        if (domain.isNotEmpty()) append(domain)
        if (ips != null) for (i in 0 until ips.length()) {
            if (isNotEmpty()) append("\n")
            append(ips.getString(i))
        }
    }
    fun pick(key: String) = result?.optString(key)?.takeIf { it.isNotEmpty() && it != "unknown" }
    val groups = listOf(
        InsightGroup(stringResource(R.string.lookup_target), listOfNotNull(
            target.takeIf { it.isNotEmpty() }, pick("registrable"))),
        InsightGroup(stringResource(R.string.lookup_location), listOfNotNull(pick("location"))),
        InsightGroup(stringResource(R.string.lookup_service), listOfNotNull(
            pick("service"), pick("owner") ?: pick("company"),
            categoryLabel(result?.optString("category")))),
        InsightGroup(stringResource(R.string.lookup_risk), listOfNotNull(
            riskLabel(result?.optString("risk")),
            confidenceLabel(result?.optString("confidence")))),
        InsightGroup(stringResource(R.string.lookup_summary), listOfNotNull(
            result?.optString("summary")?.takeIf { it.isNotEmpty() })),
    ).filter { it.lines.isNotEmpty() }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        for (group in groups) {
            Text(group.title, style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface)) {
                Text(group.lines.joinToString("\n"),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.fillMaxWidth().padding(16.dp))
            }
        }
    }
}

@Composable
private fun riskLabel(risk: String?): String? = when (risk) {
    "low" -> stringResource(R.string.lookup_risk_low)
    "medium" -> stringResource(R.string.lookup_risk_medium)
    "high" -> stringResource(R.string.lookup_risk_high)
    "unknown" -> stringResource(R.string.lookup_risk_unknown)
    else -> null
}

@Composable
private fun confidenceLabel(confidence: String?): String? = when (confidence) {
    "high" -> stringResource(R.string.lookup_confidence_high)
    "medium" -> stringResource(R.string.lookup_confidence_medium)
    "low" -> stringResource(R.string.lookup_confidence_low)
    else -> null
}

@Composable
private fun categoryLabel(category: String?): String? = when (category) {
    "cdn" -> stringResource(R.string.lookup_cat_cdn)
    "cloud" -> stringResource(R.string.lookup_cat_cloud)
    "ads" -> stringResource(R.string.lookup_cat_ads)
    "telemetry" -> stringResource(R.string.lookup_cat_telemetry)
    "social" -> stringResource(R.string.lookup_cat_social)
    "mail" -> stringResource(R.string.lookup_cat_mail)
    "streaming" -> stringResource(R.string.lookup_cat_streaming)
    "os_vendor" -> stringResource(R.string.lookup_cat_os_vendor)
    "iot" -> stringResource(R.string.lookup_cat_iot)
    "dev" -> stringResource(R.string.lookup_cat_dev)
    "security" -> stringResource(R.string.lookup_cat_security)
    "other" -> stringResource(R.string.lookup_cat_other)
    else -> null
}


