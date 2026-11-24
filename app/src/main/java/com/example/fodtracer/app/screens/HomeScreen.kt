package com.example.fodtracer.app.screens

import android.os.Build
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.FolderZip
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.fodtracer.app.components.LabCard
import com.example.fodtracer.app.components.StatusTag
import com.example.fodtracer.app.i18n.LocalFodStrings
import com.example.fodtracer.domain.interfaces.PrivilegeSnapshot
import com.example.fodtracer.domain.models.DiagnosticSession
import com.example.fodtracer.domain.models.RootState
import com.example.fodtracer.domain.models.SeLinuxMode
import com.example.ui.theme.LocalSemanticColors
import com.example.ui.theme.MonoTextStyle

data class HomeFeatureSpec(
    val id: String,
    val title: String,
    val metricBadge: String,
    val icon: ImageVector,
    val onOpen: () -> Unit
)

@Composable
fun HomeScreen(
    privilegeSnapshot: PrivilegeSnapshot,
    activeSession: DiagnosticSession?,
    sessionCount: Int,
    comparisonCount: Int,
    onOpenDiagnostic: () -> Unit,
    onOpenComparator: () -> Unit,
    onOpenSolutions: () -> Unit,
    onOpenArchives: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier
) {
    val strings = LocalFodStrings.current
    val sem = LocalSemanticColors.current
    var expandedIndex by remember { mutableIntStateOf(0) }

    val features = remember(strings, activeSession, sessionCount, comparisonCount) {
        listOf(
            HomeFeatureSpec(
                id = "diagnostic",
                title = strings.featureDiagnostic,
                metricBadge = activeSession?.let { "${it.components.size} comp / ${it.anomalies.size} anom" } ?: "Phase 1 + 2",
                icon = Icons.Filled.Fingerprint,
                onOpen = onOpenDiagnostic
            ),
            HomeFeatureSpec(
                id = "comparator",
                title = strings.featureComparator,
                metricBadge = "$comparisonCount cmp",
                icon = Icons.Filled.CompareArrows,
                onOpen = onOpenComparator
            ),
            HomeFeatureSpec(
                id = "solutions",
                title = strings.featureSolutionsAi,
                metricBadge = "${activeSession?.solutions?.size ?: 0} GSI",
                icon = Icons.Filled.Psychology,
                onOpen = onOpenSolutions
            ),
            HomeFeatureSpec(
                id = "archives",
                title = strings.featureArchives,
                metricBadge = "$sessionCount ZIP",
                icon = Icons.Filled.FolderZip,
                onOpen = onOpenArchives
            )
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        // Minimalist Lab Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = MaterialTheme.colorScheme.primaryContainer
                ) {
                    Icon(
                        imageVector = Icons.Filled.Fingerprint,
                        contentDescription = strings.appTitle,
                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(10.dp).size(24.dp)
                    )
                }
                Column {
                    Text(
                        text = strings.appTitle,
                        style = MaterialTheme.typography.displaySmall,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        text = "${Build.MANUFACTURER} ${Build.MODEL}",
                        style = MonoTextStyle,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            IconButton(
                onClick = onOpenSettings,
                modifier = Modifier
                    .minimumInteractiveComponentSize()
                    .testTag("settings_button")
            ) {
                Icon(
                    imageVector = Icons.Outlined.Settings,
                    contentDescription = strings.settings,
                    tint = MaterialTheme.colorScheme.onBackground
                )
            }
        }

        // System Telemetry Strip
        LabCard(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = "${strings.androidLabel} ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                        style = MaterialTheme.typography.labelLarge
                    )
                    Text(
                        text = Build.DEVICE,
                        style = MonoTextStyle,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                StatusTag(
                    text = if (privilegeSnapshot.publicFodDirWritable) "sdcard/FODtracer" else "Private + SAF",
                    accent = if (privilegeSnapshot.publicFodDirWritable) sem.proved else MaterialTheme.colorScheme.primary
                )
            }

            Spacer(Modifier.height(12.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outline)
            Spacer(Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val rootAccent = when (privilegeSnapshot.rootState) {
                    RootState.GRANTED_VERIFIED -> sem.proved
                    RootState.AVAILABLE_NOT_GRANTED -> sem.hypothesis
                    RootState.DENIED -> sem.critical
                    else -> sem.inaccessible
                }
                StatusTag(
                    text = "${strings.rootLabel}: ${privilegeSnapshot.rootState.name}",
                    accent = rootAccent,
                    modifier = Modifier.weight(1f)
                )

                val selinuxAccent = when (privilegeSnapshot.seLinuxMode) {
                    SeLinuxMode.ENFORCING -> MaterialTheme.colorScheme.primary
                    SeLinuxMode.PERMISSIVE -> sem.hypothesis
                    else -> sem.inaccessible
                }
                StatusTag(
                    text = "${strings.seLinuxLabel}: ${privilegeSnapshot.seLinuxMode.name}",
                    accent = selinuxAccent,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Expandable Horizontal Feature Strip
        LazyRow(
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(vertical = 4.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            itemsIndexed(features, key = { _, item -> item.id }) { index, item ->
                val isExpanded = index == expandedIndex
                Surface(
                    onClick = { expandedIndex = index },
                    shape = MaterialTheme.shapes.large,
                    color = if (isExpanded) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
                    border = BorderStroke(
                        width = if (isExpanded) 1.5.dp else 1.dp,
                        color = if (isExpanded) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
                    ),
                    modifier = Modifier
                        .width(if (isExpanded) 252.dp else 168.dp)
                        .animateContentSize(spring(stiffness = Spring.StiffnessMediumLow))
                        .testTag("feature_card_${item.id}")
                ) {
                    Column(
                        modifier = Modifier.padding(18.dp),
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = item.icon,
                                contentDescription = item.title,
                                tint = if (isExpanded) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(28.dp)
                            )
                            StatusTag(
                                text = item.metricBadge,
                                accent = MaterialTheme.colorScheme.secondary
                            )
                        }

                        Text(
                            text = item.title,
                            style = MaterialTheme.typography.titleMedium,
                            color = if (isExpanded) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface
                        )

                        AnimatedVisibility(visible = isExpanded) {
                            Button(
                                onClick = item.onOpen,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .minimumInteractiveComponentSize()
                                    .testTag("open_feature_${item.id}")
                            ) {
                                Text(strings.openFeature)
                                Spacer(Modifier.width(6.dp))
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                                    contentDescription = null,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                    }
                }
            }
        }

        // Active session compact telemetry strip if available
        activeSession?.let { session ->
            LabCard(
                onClick = onOpenDiagnostic,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(session.label, style = MaterialTheme.typography.titleMedium)
                    StatusTag(
                        text = session.environment.detectedRomType.name,
                        accent = MaterialTheme.colorScheme.primary
                    )
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "${session.sessionId} • ${session.evidence.size} EV • ${session.anomalies.size} ANOM",
                    style = MonoTextStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
