package com.redsalmons.mobilewatchdog.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.redsalmons.mobilewatchdog.R

private val Accent = Color(0xFF1A73E8)

@Composable
fun App() {
    var showSettings by rememberSaveable { mutableStateOf(false) }
    if (showSettings) {
        BackHandler { showSettings = false }
        SettingsScreen(onBack = { showSettings = false })
    } else {
        MainScreen(onSettings = { showSettings = true })
    }
}

@Composable
private fun MainScreen(onSettings: () -> Unit) {
    Box(Modifier.fillMaxSize()) {
        MapScreen(Modifier.fillMaxSize())
        Box(
            Modifier
                .align(Alignment.BottomEnd)
                .safeDrawingPadding()
                .padding(24.dp)
                .shadow(4.dp, CircleShape)
                .size(56.dp)
                .clip(CircleShape)
                .background(Accent)
                .clickable(onClick = onSettings),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Filled.Settings, contentDescription = stringResource(R.string.settings),
                tint = Color.White, modifier = Modifier.size(26.dp))
        }
    }
}

@Composable
private fun SettingsScreen(onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().background(Color.White).safeDrawingPadding()) {
        Box(Modifier.fillMaxWidth().height(44.dp)) {
            Icon(
                Icons.AutoMirrored.Filled.ArrowBack,
                contentDescription = null,
                tint = Accent,
                modifier = Modifier.align(Alignment.CenterStart).clickable(onClick = onBack).padding(10.dp),
            )
            Text(stringResource(R.string.settings), Modifier.align(Alignment.Center),
                fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
        }
        HorizontalDivider()
    }
}
