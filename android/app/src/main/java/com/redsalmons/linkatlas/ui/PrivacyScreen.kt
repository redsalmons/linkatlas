package com.redsalmons.linkatlas.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.redsalmons.linkatlas.CaptureStore
import com.redsalmons.linkatlas.R

private val Accent = Color(0xFF1A73E8)
private val PageBackground = Color(0xFFF4F6FA)
private val SecondaryText = Color(0xFF617086)
private val Good = Color(0xFF10A89A)

/** In-app data dictionary: what is read, what is not, where it lives. */
@Composable
internal fun PrivacyScreen(onBack: () -> Unit, onPolicy: () -> Unit) {
    var confirming by remember { mutableStateOf(false) }
    var cleared by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().background(PageBackground).safeDrawingPadding()) {
        SettingsHeader(stringResource(R.string.privacy_title), onBack)
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SectionCard(null, stringResource(R.string.privacy_intro), accent = true)
            SectionCard(stringResource(R.string.privacy_collect_title), stringResource(R.string.privacy_collect_body))
            SectionCard(stringResource(R.string.privacy_not_collect_title), stringResource(R.string.privacy_not_collect_body), good = true)
            SectionCard(stringResource(R.string.privacy_storage_title), stringResource(R.string.privacy_storage_body))
            SectionCard(stringResource(R.string.privacy_transfer_title), stringResource(R.string.privacy_transfer_body), good = true)
            SectionCard(stringResource(R.string.privacy_third_party_title), stringResource(R.string.privacy_third_party_body))
            SectionCard(stringResource(R.string.privacy_location_title), stringResource(R.string.privacy_location_body))
            SectionCard(stringResource(R.string.privacy_vpn_title), stringResource(R.string.privacy_vpn_body))

            Text(
                stringResource(R.string.privacy_policy_link),
                Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Color.White)
                    .clickable(onClick = onPolicy).padding(18.dp),
                color = Accent, fontSize = 15.sp, fontWeight = FontWeight.SemiBold,
            )
            Text(
                if (cleared) stringResource(R.string.privacy_cleared) else stringResource(R.string.privacy_clear),
                Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp))
                    .background(if (cleared) Color(0xFFE6F5F2) else Color.White)
                    .clickable {
                        if (cleared) {
                            cleared = false
                        } else {
                            confirming = true
                        }
                    }.padding(18.dp),
                color = if (cleared) Good else Color(0xFFD14343), fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
            )
        }
    }

    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text(stringResource(R.string.privacy_clear_confirm_title)) },
            text = { Text(stringResource(R.string.privacy_clear_confirm_body)) },
            confirmButton = {
                TextButton(onClick = {
                    CaptureStore.clearRecords()
                    confirming = false
                    cleared = true
                }) { Text(stringResource(R.string.confirm), color = Accent) }
            },
            dismissButton = {
                TextButton(onClick = { confirming = false }) {
                    Text(stringResource(R.string.cancel), color = SecondaryText)
                }
            },
        )
    }
}

@Composable
private fun SectionCard(title: String?, body: String, accent: Boolean = false, good: Boolean = false) {
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Color.White).padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        if (title != null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title, fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
                    color = if (good) Good else Accent,
                )
            }
        }
        Text(
            body,
            fontSize = if (accent) 15.sp else 14.sp,
            lineHeight = 21.sp,
            color = if (accent) Color(0xFF1B2430) else SecondaryText,
            fontWeight = if (accent) FontWeight.Medium else FontWeight.Normal,
        )
    }
}

/** Full policy text, bundled with the app so it is readable offline. */
@Composable
internal fun PrivacyPolicyScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val text = remember {
        runCatching {
            context.resources.openRawResource(R.raw.privacy_policy).bufferedReader().use { it.readText() }
        }.getOrDefault("")
    }
    Column(Modifier.fillMaxSize().background(PageBackground).safeDrawingPadding()) {
        SettingsHeader(stringResource(R.string.privacy_title), onBack)
        Text(
            text,
            Modifier.verticalScroll(rememberScrollState()).padding(20.dp),
            fontSize = 13.sp, lineHeight = 20.sp, color = Color(0xFF2B3542),
        )
    }
}
