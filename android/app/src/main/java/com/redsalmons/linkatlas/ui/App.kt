package com.redsalmons.linkatlas.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.redsalmons.linkatlas.R
import com.redsalmons.linkatlas.geo.DbIpGeoResolver
import com.redsalmons.linkatlas.CaptureStore
import com.redsalmons.linkatlas.LookupServiceClient
import com.redsalmons.linkatlas.WebsiteVisit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

private val Accent = Color(0xFF1A73E8)

private const val PAGE_DETAILS = 0
private const val PAGE_MAP = 1
private const val PAGE_PRIVACY = 2
private const val PAGE_WEBSITES = 3
private const val PAGE_POLICY = 4
private const val PAGE_LOOKUP = 5
private const val PAGE_HIDDEN = 6

@Composable
fun App(onCaptureReady: () -> Unit = {}) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var onboardingDone by remember { mutableStateOf(AppPrefs.onboardingDone(context)) }
    var legacySeen by remember { mutableStateOf(false) }
    val legacyInstalled = remember {
        runCatching {
            context.packageManager.getPackageInfo("com.redsalmons.mobilewatchdog", 0)
            true
        }.getOrDefault(false)
    }
    if (legacyInstalled && !legacySeen) {
        AlertDialog(
            onDismissRequest = { legacySeen = true },
            confirmButton = {
                TextButton(onClick = {
                    context.startActivity(android.content.Intent(android.content.Intent.ACTION_DELETE,
                        android.net.Uri.parse("package:com.redsalmons.mobilewatchdog")))
                    legacySeen = true
                }) { Text(stringResource(R.string.uninstall)) }
            },
            dismissButton = {
                TextButton(onClick = { legacySeen = true }) {
                    Text(stringResource(R.string.later))
                }
            },
            title = { Text(stringResource(R.string.legacy_app_title)) },
            text = { Text(stringResource(R.string.legacy_app_message)) },
        )
    }
    if (!onboardingDone) {
        OnboardingScreen(onFinish = {
            AppPrefs.setOnboardingDone(context)
            onboardingDone = true
        })
    } else {
        LaunchedEffect(Unit) { onCaptureReady() }
        CaptureHome()
    }
}

/** The details page is the root; the map is one of its destinations. */
@Composable
private fun CaptureHome() {
    val context = androidx.compose.ui.platform.LocalContext.current
    var page by rememberSaveable { mutableStateOf(PAGE_DETAILS) }
    var lookupSnapshot by rememberSaveable { mutableStateOf("") }
    var lookupBackTo by rememberSaveable { mutableStateOf(PAGE_WEBSITES) }
    var visits by remember { mutableStateOf(emptyList<WebsiteVisit>()) }
    var whitelist by remember { mutableStateOf(AppPrefs.whitelist(context)) }
    suspend fun pullWhitelist() {
        runCatching { LookupServiceClient.configured(context) }.getOrNull()?.fetchWhitelist()?.let {
            whitelist = it
            AppPrefs.setWhitelist(context, it)
        }
    }
    LaunchedEffect(Unit) { pullWhitelist() }
    // Also refresh on entering the map or a contact-service detail page.
    LaunchedEffect(page) {
        if (page == PAGE_MAP || page == PAGE_LOOKUP) pullWhitelist()
    }
    LaunchedEffect(Unit) {
        // Records accumulate until the app exits or the user clears them, so
        // closed flows never vanish from the UI.
        val visitsByPair = mutableMapOf<String, WebsiteVisit>()
        var lastReset = CaptureStore.resetGeneration
        while (isActive) {
            val latest = withContext(Dispatchers.Default) { CaptureStore.websiteVisits() }
            if (CaptureStore.resetGeneration != lastReset) {
                lastReset = CaptureStore.resetGeneration
                visitsByPair.clear()
            }
            latest.forEach { visitsByPair["${it.domain}|${it.ip}"] = it }
            visits = visitsByPair.values.toList()
            delay(3000)
        }
    }
    val websites = remember(visits) { groupWebsites(visits) }
    val hidden = remember(websites, whitelist) { websites.filter { whitelist.matches(it) } }
    val shown = remember(websites, whitelist) { websites.filterNot { whitelist.matches(it) } }
    val connectionCount = remember(websites) { websites.sumOf { it.tcp + it.udp } }
    BackHandler(enabled = page > 0) {
        page = when (page) {
            PAGE_LOOKUP -> lookupBackTo
            PAGE_HIDDEN -> PAGE_WEBSITES
            else -> page - 1
        }
    }
    AnimatedContent(targetState = page, transitionSpec = {
        val direction = if (targetState > initialState) 1 else -1
        slideInHorizontally { it * direction } togetherWith slideOutHorizontally { -it * direction }
    }, label = "details-navigation") { currentPage ->
        when (currentPage) {
            PAGE_DETAILS -> SettingsScreen(
                shown,
                onMap = { page = PAGE_MAP },
                onWebsites = { page = PAGE_WEBSITES },
                onPrivacy = { page = PAGE_PRIVACY },
                hiddenCount = hidden.size,
                connectionCount = connectionCount,
            )
            PAGE_MAP -> MapPage(shown, onBack = { page = PAGE_DETAILS })
            PAGE_PRIVACY -> PrivacyScreen(
                onBack = { page = PAGE_DETAILS },
                onPolicy = { page = PAGE_POLICY },
            )
            PAGE_WEBSITES -> WebsitesScreen(shown, hidden.size, onBack = { page = PAGE_DETAILS },
                onSelect = { lookupSnapshot = it.snapshot(); lookupBackTo = PAGE_WEBSITES; page = PAGE_LOOKUP },
                onHidden = { page = PAGE_HIDDEN }, connectionCount = connectionCount)
            PAGE_HIDDEN -> WebsitesScreen(hidden, 0, onBack = { page = PAGE_WEBSITES },
                onSelect = { lookupSnapshot = it.snapshot(); lookupBackTo = PAGE_HIDDEN; page = PAGE_LOOKUP },
                titleRes = R.string.filtered_services)
            PAGE_LOOKUP -> LookupDetailScreen(lookupSnapshot, onBack = { page = lookupBackTo })
            else -> PrivacyPolicyScreen(onBack = { page = PAGE_PRIVACY })
        }
    }
}

@Composable
private fun MapPage(websites: List<WebsiteStat>, onBack: () -> Unit) {
    var recenter by remember { mutableStateOf(0) }
    Box(Modifier.fillMaxSize()) {
        MapScreen(Modifier.fillMaxSize(), recenterTick = recenter, onBack = onBack)
        Row(
            Modifier.align(Alignment.TopCenter).fillMaxWidth()
                .statusBarsPadding().padding(start = 12.dp, end = 12.dp, top = 6.dp),
            verticalAlignment = Alignment.Top,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Box(
                Modifier
                    .shadow(4.dp, CircleShape)
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(Color.White.copy(alpha = 0.92f))
                    .clickable(onClick = onBack),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.back),
                    tint = Accent, modifier = Modifier.size(22.dp))
            }
            LiveStatsOverlay(websites, Modifier.weight(1f))
        }
        Column(
            Modifier.align(Alignment.BottomEnd).safeDrawingPadding().padding(12.dp),
            horizontalAlignment = Alignment.End,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(
                Modifier
                    .shadow(4.dp, CircleShape)
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(Color.White.copy(alpha = 0.92f))
                    .clickable { recenter += 1 },
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Filled.LocationOn,
                    contentDescription = stringResource(R.string.map_recenter),
                    tint = Accent, modifier = Modifier.size(22.dp))
            }
            Text(
                DbIpGeoResolver.ATTRIBUTION + stringResource(R.string.geoip_approx),
                Modifier.padding(horizontal = 6.dp, vertical = 3.dp),
                fontSize = 10.sp, color = Color(0xFF444444)
            )
        }
    }
}

/** Bytes-only summary; the connection counts lived here before and squeezed it. */
@Composable
private fun LiveStatsOverlay(websites: List<WebsiteStat>, modifier: Modifier = Modifier) {
    val byBytes = websites.filter { it.bytes > 0 }.sortedByDescending { it.bytes }.take(6)
    if (byBytes.isEmpty()) return
    Column(
        modifier
            .background(Color.Black.copy(alpha = 0.45f))
            .padding(horizontal = 14.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(stringResource(R.string.overview_bytes), fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = Color.White)
        byBytes.chunked(2).forEach { pair ->
            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                pair.forEach {
                    Text("${it.title.take(18)}  ${formatBytes(it.bytes)}", fontSize = 10.sp,
                        color = Color.White.copy(alpha = 0.85f), maxLines = 1,
                        modifier = Modifier.weight(1f))
                }
                if (pair.size == 1) Box(Modifier.weight(1f))
            }
        }
    }
}
