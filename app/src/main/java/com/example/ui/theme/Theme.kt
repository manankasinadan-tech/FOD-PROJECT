package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.example.fodtracer.domain.models.ThemePreference

@Immutable
data class SemanticLabColors(
    val proved: Color,
    val correlated: Color,
    val hypothesis: Color,
    val inaccessible: Color,
    val critical: Color
)

val LocalSemanticColors = staticCompositionLocalOf {
    SemanticLabColors(
        proved = StatusProvedLight,
        correlated = StatusCorrelatedLight,
        hypothesis = StatusHypothesisLight,
        inaccessible = StatusInaccessibleLight,
        critical = StatusCriticalLight
    )
}

private val LightLabColorScheme = lightColorScheme(
    primary = LabPrimary,
    onPrimary = LabOnPrimary,
    primaryContainer = LabPrimaryContainer,
    onPrimaryContainer = LabOnPrimaryContainer,
    secondary = LabAccent,
    onSecondary = LabOnAccent,
    secondaryContainer = LabAccentContainer,
    onSecondaryContainer = LabOnAccentContainer,
    background = LabBackground,
    onBackground = LabTextPrimary,
    surface = LabSurface,
    onSurface = LabTextPrimary,
    surfaceVariant = LabSurfaceVariant,
    onSurfaceVariant = LabTextSecondary,
    outline = LabOutline,
    error = StatusCriticalLight,
    onError = Color.White
)

private val DarkTechColorScheme = darkColorScheme(
    primary = TechPrimary,
    onPrimary = TechOnPrimary,
    primaryContainer = TechPrimaryContainer,
    onPrimaryContainer = TechOnPrimaryContainer,
    secondary = TechAccent,
    onSecondary = TechOnAccent,
    secondaryContainer = TechAccentContainer,
    onSecondaryContainer = TechOnAccentContainer,
    background = TechBackground,
    onBackground = TechTextPrimary,
    surface = TechSurface,
    onSurface = TechTextPrimary,
    surfaceVariant = TechSurfaceVariant,
    onSurfaceVariant = TechTextSecondary,
    outline = TechOutline,
    error = StatusCriticalDark,
    onError = Color(0xFF450A0A)
)

private val LabShapes = Shapes(
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp)
)

@Composable
fun FodTracerTheme(
    themePreference: ThemePreference = ThemePreference.LIGHT,
    content: @Composable () -> Unit
) {
    val useDark = when (themePreference) {
        ThemePreference.LIGHT -> false
        ThemePreference.DARK -> true
        ThemePreference.SYSTEM -> isSystemInDarkTheme()
    }

    val colorScheme = if (useDark) DarkTechColorScheme else LightLabColorScheme
    val semanticColors = if (useDark) {
        SemanticLabColors(
            proved = StatusProvedDark,
            correlated = StatusCorrelatedDark,
            hypothesis = StatusHypothesisDark,
            inaccessible = StatusInaccessibleDark,
            critical = StatusCriticalDark
        )
    } else {
        SemanticLabColors(
            proved = StatusProvedLight,
            correlated = StatusCorrelatedLight,
            hypothesis = StatusHypothesisLight,
            inaccessible = StatusInaccessibleLight,
            critical = StatusCriticalLight
        )
    }

    CompositionLocalProvider(LocalSemanticColors provides semanticColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = Typography,
            shapes = LabShapes,
            content = content
        )
    }
}
