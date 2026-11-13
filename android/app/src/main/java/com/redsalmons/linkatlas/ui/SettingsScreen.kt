package com.redsalmons.linkatlas.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Place
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.redsalmons.linkatlas.R
import com.redsalmons.linkatlas.WebsiteVisit
import java.util.Locale

internal data class WebsiteStat(
    val key: String, val domain: String, val ips: List<String>, val tcp: Long, val udp: Long,
    val bytesOut: Long, val bytesIn: Long,
) {
    val title: String get() = domain.ifEmpty { ips.first() }
    val bytes: Long get() = bytesOut + bytesIn
}

internal fun groupWebsites(visits: List<WebsiteVisit>): List<WebsiteStat> =
    visits.groupBy {
        if (it.domain.isBlank()) "ip:${it.ip}" else "domain:${it.domain.lowercase(Locale.ROOT)}"
    }.map { (key, records) ->
        WebsiteStat(key, records.first().domain.lowercase(Locale.ROOT),
            records.map { it.ip }.distinct().sorted(),
            records.sumOf { it.tcpConnections }, records.sumOf { it.udpFlows },
            records.sumOf { it.bytesOut }, records.sumOf { it.bytesIn })
    }.sortedWith(compareByDescending<WebsiteStat> { it.tcp }.thenBy { it.title })

private val ChartColors = listOf(
    Color(0xFF1A73E8), Color(0xFF10A89A), Color(0xFFF4B042),
    Color(0xFF8662D9), Color(0xFFEC7185), Color(0xFF9AA8BA),
)
private val PageBackground = Color(0xFFF4F6FA)
private val Accent = Color(0xFF1A73E8)
private val SecondaryText = Color(0xFF617086)

@Composable
internal fun SettingsScreen(websites: List<WebsiteStat>, onMap: () -> Unit,
                            onWebsites: () -> Unit, onPrivacy: () -> Unit,
                            hiddenCount: Int = 0, connectionCount: Long = 0) {
    Column(Modifier.fillMaxSize().background(PageBackground).safeDrawingPadding()) {
        SettingsHeader(stringResource(R.string.app_name))
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp)) {
            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(Color.White)
                .padding(20.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.summary), fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                    Text(stringResource(R.string.services_summary,
                        websites.size + hiddenCount, connectionCount, hiddenCount),
                        color = SecondaryText, fontSize = 14.sp)
                }
            }
            TrafficRank(websites)
            ConnectionPie(websites)
            MapRow(onMap)
            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Color.White)
                .clickable(onClick = onWebsites).padding(20.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.communication_services), fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                    Text(stringResource(R.string.website_count, websites.size), color = SecondaryText, fontSize = 13.sp)
                }
                Text("›", fontSize = 28.sp, color = SecondaryText)
            }
            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Color.White)
                .clickable(onClick = onPrivacy).padding(20.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.privacy_title), fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                    Text(stringResource(R.string.privacy_clear), color = SecondaryText, fontSize = 13.sp)
                }
                Text("›", fontSize = 28.sp, color = SecondaryText)
            }
            Text(stringResource(R.string.session_statistics_note), color = SecondaryText, fontSize = 12.sp)
        }
    }
}

internal fun formatBytes(bytes: Long): String = when {
    bytes >= 1L shl 30 -> "%.1f GB".format(bytes / 1073741824.0)
    bytes >= 1L shl 20 -> "%.1f MB".format(bytes / 1048576.0)
    bytes >= 1L shl 10 -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

private data class PieSlice(val name: String, val value: Long, val color: Color)

private fun topSlices(entries: List<Pair<String, Long>>, other: String): List<PieSlice> {
    val items = entries.filter { it.second > 0 }.sortedByDescending { it.second }
    val shown = items.take(5)
    val remainder = items.drop(5).sumOf { it.second }
    val all = if (remainder > 0) shown + (other to remainder) else shown
    return all.mapIndexed { index, (name, value) -> PieSlice(name, value, ChartColors[index]) }
}

@Composable
private fun TrafficRank(websites: List<WebsiteStat>) {
    val total = websites.sumOf { it.bytes }
    val top = websites.filter { it.bytes > 0 }.sortedByDescending { it.bytes }.take(5)
    ChartCard(stringResource(R.string.traffic_rank), stringResource(R.string.total_traffic, formatBytes(total))) {
        if (total == 0L) EmptyChart(stringResource(R.string.no_connections))
        top.forEachIndexed { index, website ->
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(website.title, Modifier.weight(1f), maxLines = 1,
                        overflow = TextOverflow.Ellipsis, fontSize = 13.sp)
                    Text(formatBytes(website.bytes), fontSize = 12.sp, color = SecondaryText)
                }
                Box(Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp))
                    .background(Color(0xFFE8EDF4))) {
                    Box(Modifier.fillMaxWidth((website.bytes.toDouble() / top[0].bytes).toFloat())
                        .fillMaxHeight().clip(RoundedCornerShape(4.dp))
                        .background(ChartColors[index % ChartColors.size]))
                }
                Text(stringResource(R.string.traffic_out_in, formatBytes(website.bytesOut),
                    formatBytes(website.bytesIn)), fontSize = 11.sp, color = SecondaryText)
            }
        }
    }
}

@Composable
private fun ConnectionPie(websites: List<WebsiteStat>) {
    val total = websites.sumOf { it.tcp + it.udp }
    val slices = topSlices(websites.map { it.title to (it.tcp + it.udp) },
        stringResource(R.string.other_websites))
    LegendPie(stringResource(R.string.connection_distribution),
        stringResource(R.string.protocol_total, total), slices, total,
        stringResource(R.string.no_connections))
}

@Composable
private fun ChartCard(title: String, subtitle: String, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(Color.White).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(title, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
        Text(subtitle, color = SecondaryText, fontSize = 14.sp)
        content()
    }
}

@Composable
private fun EmptyChart(text: String) {
    Text(text, color = SecondaryText, modifier = Modifier.fillMaxWidth().padding(vertical = 32.dp),
        textAlign = androidx.compose.ui.text.style.TextAlign.Center)
}

/** Plain pie with a legend below (name + percentage). */
@Composable
private fun LegendPie(title: String, subtitle: String, slices: List<PieSlice>,
                      total: Long, emptyText: String) {
    ChartCard(title, subtitle) {
        if (total == 0L || slices.isEmpty()) {
            EmptyChart(emptyText)
            return@ChartCard
        }
        Canvas(Modifier.size(160.dp).align(Alignment.CenterHorizontally).semantics {
            contentDescription = subtitle
        }) {
            var start = -90f
            slices.forEach { slice ->
                val sweep = slice.value.toFloat() / total * 360f
                drawArc(slice.color, start, sweep, useCenter = true)
                start += sweep
            }
        }
        slices.forEach { slice ->
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Box(Modifier.size(10.dp).clip(RoundedCornerShape(3.dp)).background(slice.color))
                Text(slice.name, Modifier.weight(1f), maxLines = 1,
                    overflow = TextOverflow.Ellipsis, fontSize = 13.sp)
                Text(stringResource(R.string.connection_slice, slice.value,
                    slice.value.toDouble() / total * 100), color = SecondaryText, fontSize = 12.sp)
            }
        }
    }
}

@Composable
internal fun WebsitesScreen(websites: List<WebsiteStat>, hiddenCount: Int = 0,
                            onBack: () -> Unit, onSelect: (WebsiteStat) -> Unit = {},
                            onHidden: () -> Unit = {}, titleRes: Int = R.string.communication_services,
                            connectionCount: Long = 0) {
    var query by rememberSaveable { mutableStateOf("") }
    val filtered = remember(websites, query) {
        val term = query.trim()
        websites.filter { it.title.contains(term, ignoreCase = true) || it.ips.any { ip -> ip.contains(term, true) } }
    }
    Column(Modifier.fillMaxSize().background(PageBackground).safeDrawingPadding()) {
        SettingsHeader(stringResource(titleRes), onBack)
        OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth().padding(16.dp),
            placeholder = { Text(stringResource(R.string.search_domain_ip)) }, singleLine = true,
            shape = RoundedCornerShape(14.dp))
        Text(stringResource(R.string.website_count, filtered.size), color = SecondaryText, fontSize = 12.sp,
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp))
        if (filtered.isEmpty() && hiddenCount == 0) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(stringResource(if (query.isBlank()) R.string.no_websites else R.string.no_matching_websites),
                    color = SecondaryText)
            }
        } else {
            val summaryNote = if (titleRes == R.string.filtered_services)
                stringResource(R.string.filtered_services_note, websites.size)
            else stringResource(R.string.services_summary,
                websites.size + hiddenCount, connectionCount, hiddenCount)
            LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                item(key = "summary") {
                    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp))
                        .background(Color(0xFFE8F0FE)).padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(stringResource(R.string.summary), fontSize = 15.sp,
                                fontWeight = FontWeight.SemiBold, color = Accent)
                            Text(summaryNote, color = SecondaryText, fontSize = 12.sp)
                        }
                    }
                }
                items(filtered, key = { it.key }) { website ->
                    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp))
                        .background(Color.White).clickable { onSelect(website) }.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(website.title, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                                if (website.domain.isNotEmpty()) {
                                    Text(website.ips.joinToString("\n"), color = SecondaryText, fontSize = 13.sp)
                                } else {
                                    Text(stringResource(R.string.domain_unlabeled), color = SecondaryText, fontSize = 12.sp)
                                }
                            }
                            Text(stringResource(R.string.website_connections, website.tcp, website.udp),
                                color = Color(0xFF1A73E8), fontSize = 12.sp)
                            Text(stringResource(R.string.traffic_out_in, formatBytes(website.bytesOut),
                                formatBytes(website.bytesIn)), color = SecondaryText, fontSize = 11.sp)
                        }
                        Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null,
                            tint = SecondaryText, modifier = Modifier.size(22.dp))
                    }
                }
                if (hiddenCount > 0) {
                    item(key = "filtered-entry") {
                        Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp))
                            .background(Color.White).clickable(onClick = onHidden).padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(stringResource(R.string.filtered_services),
                                    fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                                Text(stringResource(R.string.filtered_services_note, hiddenCount),
                                    color = SecondaryText, fontSize = 12.sp)
                            }
                            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null,
                                tint = SecondaryText, modifier = Modifier.size(22.dp))
                        }
                    }
                }
            }
        }
    }
}

@Composable
internal fun SettingsHeader(title: String, onBack: (() -> Unit)? = null) {
    Box(Modifier.fillMaxWidth().height(52.dp).background(Color.White)) {
        if (onBack != null) {
            IconButton(onClick = onBack, modifier = Modifier.align(Alignment.CenterStart)) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back),
                    tint = Color(0xFF1A73E8))
            }
        }
        Text(title, Modifier.align(Alignment.Center), fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
    }
}

/** Entry point to the world map. */
@Composable
private fun MapRow(onMap: () -> Unit) {
    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Color.White)
        .clickable(onClick = onMap).padding(20.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp)) {
        Box(Modifier.size(40.dp).clip(RoundedCornerShape(12.dp)).background(Color(0xFFE8F0FE)),
            contentAlignment = Alignment.Center) {
            Icon(Icons.Filled.Place, contentDescription = null, tint = Accent,
                modifier = Modifier.size(22.dp))
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.connection_map), fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            Text(stringResource(R.string.connection_map_note), color = SecondaryText, fontSize = 13.sp)
        }
        Text("›", fontSize = 28.sp, color = SecondaryText)
    }
}
