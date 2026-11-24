package com.example.fodtracer.app.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.fodtracer.domain.models.*
import com.example.ui.theme.LocalSemanticColors
import com.example.ui.theme.MonoTextStyle

@Composable
fun LabCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    val border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    if (onClick != null) {
        Surface(
            onClick = onClick,
            modifier = modifier,
            shape = MaterialTheme.shapes.medium,
            color = MaterialTheme.colorScheme.surface,
            border = border,
            tonalElevation = 0.dp
        ) {
            Column(modifier = Modifier.padding(16.dp), content = content)
        }
    } else {
        Surface(
            modifier = modifier,
            shape = MaterialTheme.shapes.medium,
            color = MaterialTheme.colorScheme.surface,
            border = border,
            tonalElevation = 0.dp
        ) {
            Column(modifier = Modifier.padding(16.dp), content = content)
        }
    }
}

@Composable
fun EpistemicBadge(level: EpistemicLevel, modifier: Modifier = Modifier) {
    val sem = LocalSemanticColors.current
    val (color, label) = when (level) {
        EpistemicLevel.PROVED -> sem.proved to "PROVED"
        EpistemicLevel.CORRELATED -> sem.correlated to "CORRELATED"
        EpistemicLevel.HYPOTHESIS -> sem.hypothesis to "HYPOTHESIS"
        EpistemicLevel.INACCESSIBLE -> sem.inaccessible to "INACCESSIBLE"
    }
    StatusTag(text = label, accent = color, modifier = modifier)
}

@Composable
fun DiscoveryStatusTag(status: DiscoveryStatus, modifier: Modifier = Modifier) {
    val sem = LocalSemanticColors.current
    val color = when (status) {
        DiscoveryStatus.FOUND -> sem.proved
        DiscoveryStatus.PARTIAL -> sem.hypothesis
        DiscoveryStatus.INACCESSIBLE -> sem.inaccessible
        DiscoveryStatus.NOT_FOUND -> MaterialTheme.colorScheme.onSurfaceVariant
        DiscoveryStatus.UNSUPPORTED -> MaterialTheme.colorScheme.onSurfaceVariant
        DiscoveryStatus.ERROR -> sem.critical
    }
    StatusTag(text = status.name, accent = color, modifier = modifier)
}

@Composable
fun StatusTag(
    text: String,
    accent: Color,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .background(accent.copy(alpha = 0.12f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = accent,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
fun MonoCodeBlock(
    text: String,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceVariant
    ) {
        Text(
            text = text,
            style = MonoTextStyle,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(10.dp)
        )
    }
}

@Composable
fun DependencyGraphCanvas(
    components: List<DiscoveredComponent>,
    links: List<DependencyLink>,
    modifier: Modifier = Modifier
) {
    val sem = LocalSemanticColors.current
    val primary = MaterialTheme.colorScheme.primary
    val onSurface = MaterialTheme.colorScheme.onSurface
    val outline = MaterialTheme.colorScheme.outline
    val textMeasurer = rememberTextMeasurer()

    LabCard(modifier = modifier.fillMaxWidth()) {
        Text(
            text = "FOD Architecture Chain (${components.size} nodes, ${links.size} links)",
            style = MaterialTheme.typography.titleMedium
        )
        Spacer(Modifier.height(8.dp))

        val rolesOrder = listOf(
            ComponentRole.RESOURCE_OVERLAY to "RRO",
            ComponentRole.APPLICATION_SYSTEMUI to "SystemUI",
            ComponentRole.BIOMETRIC_SERVICE to "BioSvc",
            ComponentRole.BIOMETRIC_HAL to "HAL",
            ComponentRole.TOUCH_CONTROLLER to "Touch",
            ComponentRole.DISPLAY_HBM to "HBM",
            ComponentRole.KERNEL_DRIVER to "Kernel"
        )

        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(176.dp)
        ) {
            val w = size.width
            val h = size.height
            val nodeW = w / 4.5f
            val nodeH = 42.dp.toPx()

            val nodeCenters = mapOf(
                ComponentRole.RESOURCE_OVERLAY to Offset(w * 0.13f, h * 0.25f),
                ComponentRole.APPLICATION_SYSTEMUI to Offset(w * 0.37f, h * 0.25f),
                ComponentRole.BIOMETRIC_SERVICE to Offset(w * 0.62f, h * 0.25f),
                ComponentRole.BIOMETRIC_HAL to Offset(w * 0.87f, h * 0.25f),
                ComponentRole.TOUCH_CONTROLLER to Offset(w * 0.22f, h * 0.75f),
                ComponentRole.DISPLAY_HBM to Offset(w * 0.52f, h * 0.75f),
                ComponentRole.KERNEL_DRIVER to Offset(w * 0.82f, h * 0.75f)
            )

            links.forEach { link ->
                val fromComp = components.firstOrNull { it.id == link.fromComponentId }
                val toComp = components.firstOrNull { it.id == link.toComponentId }
                val p1 = fromComp?.role?.let { nodeCenters[it] }
                val p2 = toComp?.role?.let { nodeCenters[it] }
                if (p1 != null && p2 != null) {
                    val lineColor = when {
                        link.observed -> sem.proved
                        link.epistemicLevel == EpistemicLevel.INACCESSIBLE -> sem.inaccessible
                        else -> sem.hypothesis
                    }
                    val effect = if (link.observed) null else PathEffect.dashPathEffect(floatArrayOf(10f, 8f))
                    drawLine(
                        color = lineColor,
                        start = p1,
                        end = p2,
                        strokeWidth = if (link.observed) 2.5.dp.toPx() else 1.8.dp.toPx(),
                        pathEffect = effect
                    )
                }
            }

            rolesOrder.forEach { (role, label) ->
                val center = nodeCenters[role] ?: return@forEach
                val comp = components.firstOrNull { it.role == role }
                val statusColor = when (comp?.discoveryStatus) {
                    DiscoveryStatus.FOUND -> sem.proved
                    DiscoveryStatus.PARTIAL -> sem.hypothesis
                    DiscoveryStatus.INACCESSIBLE -> sem.inaccessible
                    else -> outline
                }
                val topLeft = Offset(center.x - nodeW / 2f, center.y - nodeH / 2f)
                drawRoundRect(
                    color = primary.copy(alpha = 0.08f),
                    topLeft = topLeft,
                    size = Size(nodeW, nodeH),
                    cornerRadius = CornerRadius(10.dp.toPx())
                )
                drawRoundRect(
                    color = statusColor,
                    topLeft = topLeft,
                    size = Size(nodeW, nodeH),
                    cornerRadius = CornerRadius(10.dp.toPx()),
                    style = Stroke(width = 1.8.dp.toPx())
                )
                val measured = textMeasurer.measure(
                    text = label,
                    style = TextStyle(color = onSurface, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                )
                drawText(
                    textLayoutResult = measured,
                    topLeft = Offset(
                        center.x - measured.size.width / 2f,
                        center.y - measured.size.height / 2f
                    )
                )
            }
        }

        Spacer(Modifier.height(6.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("— Solid: Observed", style = MaterialTheme.typography.labelSmall, color = sem.proved)
            Text("-- Dashed: Unverified/Expected", style = MaterialTheme.typography.labelSmall, color = sem.hypothesis)
        }
    }
}
