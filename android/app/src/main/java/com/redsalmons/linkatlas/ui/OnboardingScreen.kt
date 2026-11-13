package com.redsalmons.linkatlas.ui

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animate
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.redsalmons.linkatlas.R
import kotlinx.coroutines.delay
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin
import kotlin.random.Random

private val Accent = Color(0xFF1A73E8)
private val PointText = Color(0xFF5B6779)
private val GreetingGradient = listOf(Color(0xFF16202E), Color(0xFF3F7BF0))

/**
 * First run. One screen, three claims, no skip: this is the whole privacy story,
 * so it is read once before capture starts. The greeting spins in from a random
 * angle and repeats every few seconds; the three claims ripple like a flag.
 */
@Composable
fun OnboardingScreen(onFinish: () -> Unit) {
    var angle by remember { mutableFloatStateOf(0f) }
    var pointsIn by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        // Let the window transition finish first, otherwise the spin is hidden
        // by the launch zoom.
        delay(220)
        var first = true
        while (true) {
            val turns = 2f * 360f
            val offset = Random.nextInt(0, 360).toFloat()
            val start = if (Random.nextBoolean()) turns + offset else -(turns + offset)
            animate(
                initialValue = start,
                targetValue = 0f,
                animationSpec = tween(1600, easing = CubicBezierEasing(0.45f, 0f, 0.15f, 1f)),
            ) { value, _ -> angle = value }
            if (first) {
                first = false
                pointsIn = true
            }
            delay(Random.nextLong(3000, 5001))
        }
    }
    val pointsAlpha by animateFloatAsState(
        targetValue = if (pointsIn) 1f else 0f,
        animationSpec = tween(500),
        label = "points-in",
    )

    val points = listOf(
        R.string.onboarding_point_1,
        R.string.onboarding_point_2,
        R.string.onboarding_point_3,
    )

    Column(
        Modifier.fillMaxSize().background(Color.White).safeDrawingPadding()
            .padding(horizontal = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.weight(1f))

        WavingGreeting(
            text = stringResource(R.string.onboarding_hello),
            modifier = Modifier.rotate(angle),
        )

        Spacer(Modifier.height(34.dp))

        Column(
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            points.forEachIndexed { index, point ->
                WavingLine(
                    text = stringResource(point),
                    alpha = pointsAlpha,
                    // Offset each row so the three lines ripple like one cloth.
                    phaseOffset = index * 0.45f,
                    modifier = Modifier.offset(y = ((1f - pointsAlpha) * 8).dp),
                )
            }
        }

        Spacer(Modifier.weight(1f))

        Button(
            onClick = onFinish,
            Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(26.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Accent),
        ) {
            Text(stringResource(R.string.onboarding_start), fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold, color = Color.White)
        }
        Spacer(Modifier.height(12.dp))
    }
}

/** The greeting rendered glyph-by-glyph so it ripples like the lines below. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun WavingGreeting(text: String, modifier: Modifier = Modifier) {
    val transition = rememberInfiniteTransition(label = "greeting-wave")
    val phase by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2 * PI).toFloat(),
        animationSpec = infiniteRepeatable(tween(2800, easing = LinearEasing)),
        label = "greeting-phase",
    )
    FlowRow(modifier = modifier, horizontalArrangement = Arrangement.Center) {
        text.forEachIndexed { index, char ->
            Text(
                char.toString(),
                fontSize = 64.sp,
                fontWeight = FontWeight.Light,
                letterSpacing = 0.5.sp,
                style = TextStyle(brush = Brush.verticalGradient(GreetingGradient)),
                modifier = Modifier.graphicsLayer {
                    val wave = phase + index * 0.55f
                    translationY = sin(wave) * 5.dp.toPx()
                    rotationZ = cos(wave) * 2.2f
                },
            )
        }
    }
}

/** One line of text where every glyph lags the previous one, so the row flutters. */
@Composable
private fun WavingLine(
    text: String,
    alpha: Float,
    phaseOffset: Float,
    modifier: Modifier = Modifier,
) {
    val transition = rememberInfiniteTransition(label = "flag")
    val phase by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2 * PI).toFloat(),
        animationSpec = infiniteRepeatable(tween(2800, easing = LinearEasing)),
        label = "flag-phase",
    )
    Row(modifier) {
        text.forEachIndexed { index, char ->
            Text(
                char.toString(),
                fontSize = 16.sp,
                color = PointText.copy(alpha = alpha),
                modifier = Modifier.graphicsLayer {
                    val wave = phase + phaseOffset + index * 0.55f
                    translationY = sin(wave) * 2.6.dp.toPx()
                    rotationZ = cos(wave) * 2.2f
                },
            )
        }
    }
}
