package com.example.fodtracer.app.screens

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.example.fodtracer.app.components.*
import com.example.fodtracer.app.i18n.LocalFodStrings
import com.example.fodtracer.domain.models.*
import com.example.fodtracer.presentation.diagnostic.*
import com.example.fodtracer.workers.live.LiveTraceProgress
import com.example.ui.theme.LocalSemanticColors
import com.example.ui.theme.MonoTextStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiagnosticScreen(
    coldState: ColdRunUiState,
    activeSession: DiagnosticSession?,
    liveProgress: LiveTraceProgress,
    selectedSection: DashboardSection,
    aiState: AiUiState,
    showAiConsentDialog: Boolean,
    isFirebaseAiAvailable: Boolean,
    statusMessage: String?,
    onBack: () -> Unit,
    onSelectSection: (DashboardSection) -> Unit,
    onStartColdAnalysis: () -> Unit,
    onStartLiveEnrollment: () -> Intent?,
    onStopLiveTrace: () -> Unit,
    onRequestAiConsent: () -> Unit,
    onDismissAiConsent: () -> Unit,
    onConfirmAiAnalysis: () -> Unit,
    onClearStatusMessage: () -> Unit,
    modifier: Modifier = Modifier
) {
    val strings = LocalFodStrings.current
    val context = LocalContext.current
    val sem = LocalSemanticColors.current

    val enrollLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        // Enrollment Activity returned; let user inspect or finalize cleanly.
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) {
        val intent = onStartLiveEnrollment()
        if (intent != null) {
            runCatching { enrollLauncher.launch(intent) }
        }
    }

    if (showAiConsentDialog) {
        AlertDialog(
            onDismissRequest = onDismissAiConsent,
            title = { Text(strings.aiConsentTitle) },
            text = { Text(strings.aiConsentBody) },
            confirmButton = {
                Button(onClick = onConfirmAiAnalysis) { Text(strings.aiConsentConfirm) }
            },
            dismissButton = {
                TextButton(onClick = onDismissAiConsent) { Text(strings.aiConsentCancel) }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(strings.featureDiagnostic, style = MaterialTheme.typography.titleLarge) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.minimumInteractiveComponentSize()) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = strings.back)
                    }
                }
            )
        },
        modifier = modifier
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            statusMessage?.let { msg ->
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(msg, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                        TextButton(onClick = onClearStatusMessage) { Text("OK") }
                    }
                }
            }

            // Primary Phase 1 & Phase 2 action controls
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = onStartColdAnalysis,
                    enabled = coldState !is ColdRunUiState.Running && !liveProgress.isRunning,
                    modifier = Modifier
                        .weight(1f)
                        .minimumInteractiveComponentSize()
                        .testTag("run_cold_analysis_button")
                ) {
                    Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(strings.runColdAnalysis)
                }

                if (!liveProgress.isRunning) {
                    FilledTonalButton(
                        onClick = {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                            ) {
                                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                            } else {
                                val intent = onStartLiveEnrollment()
                                if (intent != null) {
                                    runCatching { enrollLauncher.launch(intent) }
                                }
                            }
                        },
                        enabled = activeSession != null && coldState !is ColdRunUiState.Running,
                        modifier = Modifier
                            .weight(1.3f)
                            .minimumInteractiveComponentSize()
                            .testTag("open_enrollment_button")
                    ) {
                        Icon(Icons.Filled.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(strings.openEnrollment, maxLines = 1)
                    }
                } else {
                    Button(
                        onClick = onStopLiveTrace,
                        colors = ButtonDefaults.buttonColors(containerColor = sem.critical),
                        modifier = Modifier
                            .weight(1.3f)
                            .minimumInteractiveComponentSize()
                            .testTag("stop_live_trace_button")
                    ) {
                        Icon(Icons.Filled.Stop, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(strings.stopLiveTrace, maxLines = 1)
                    }
                }
            }

            if (coldState is ColdRunUiState.Running) {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    val fraction = coldState.progress.completedCount.toFloat() / coldState.progress.totalCount.coerceAtLeast(1)
                    Text(
                        "${strings.analyzingPhase1}: ${coldState.progress.currentDomain.name} (${coldState.progress.completedCount}/${coldState.progress.totalCount})",
                        style = MaterialTheme.typography.labelLarge
                    )
                    Spacer(Modifier.height(8.dp))
                    LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
                }
            } else if (coldState is ColdRunUiState.Error) {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Text(coldState.message, color = sem.critical, style = MaterialTheme.typography.bodyMedium)
                }
            }

            if (liveProgress.isRunning) {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(strings.liveTracingActive, style = MaterialTheme.typography.labelLarge, color = sem.correlated)
                        Text("${liveProgress.eventCount} evt • ${liveProgress.elapsedMs}ms", style = MonoTextStyle)
                    }
                    liveProgress.latestEventSummary?.let {
                        Spacer(Modifier.height(4.dp))
                        Text(it, style = MonoTextStyle, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }

            if (activeSession == null) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Icon(
                            Icons.Filled.Fingerprint,
                            contentDescription = null,
                            modifier = Modifier.size(48.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Text(strings.noDiagnosticYet, style = MaterialTheme.typography.bodyLarge)
                    }
                }
            } else {
                // 10-Section Dashboard Strip
                val sections = listOf(
                    DashboardSection.OVERVIEW to strings.tabOverview,
                    DashboardSection.COMPONENTS to strings.tabComponents,
                    DashboardSection.DEPENDENCIES to strings.tabDependencies,
                    DashboardSection.TIMELINE to strings.tabTimeline,
                    DashboardSection.EVIDENCE to strings.tabEvidence,
                    DashboardSection.ANOMALIES to strings.tabAnomalies,
                    DashboardSection.CORRELATIONS to strings.tabCorrelations,
                    DashboardSection.HYPOTHESES to strings.tabHypotheses,
                    DashboardSection.INACCESSIBLE to strings.tabInaccessible,
                    DashboardSection.SYNTHESIS to strings.tabSynthesis
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    sections.forEach { (sec, label) ->
                        FilterChip(
                            selected = selectedSection == sec,
                            onClick = { onSelectSection(sec) },
                            label = { Text(label) }
                        )
                    }
                }

                DashboardSectionContent(
                    section = selectedSection,
                    session = activeSession,
                    aiState = aiState,
                    isFirebaseAiAvailable = isFirebaseAiAvailable,
                    onRequestAiConsent = onRequestAiConsent,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun DashboardSectionContent(
    section: DashboardSection,
    session: DiagnosticSession,
    aiState: AiUiState,
    isFirebaseAiAvailable: Boolean,
    onRequestAiConsent: () -> Unit,
    modifier: Modifier = Modifier
) {
    val strings = LocalFodStrings.current
    val sem = LocalSemanticColors.current

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(bottom = 24.dp)
    ) {
        when (section) {
            DashboardSection.OVERVIEW -> {
                item {
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Text(session.label, style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(6.dp))
                        MonoCodeBlock(
                            "Session: ${session.sessionId}\n" +
                                "SoC: ${session.environment.socManufacturer} ${session.environment.socModel}\n" +
                                "ROM: ${session.environment.detectedRomType} (${session.environment.romTypeEvidence})\n" +
                                "Biometric API: ${session.environment.biometricHardwareStatus}\n" +
                                "Root: ${session.environment.rootState} | SELinux: ${session.environment.seLinuxMode}"
                        )
                    }
                }
                items(session.probeResults, key = { it.probeId }) { probe ->
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(probe.domain.name, style = MaterialTheme.typography.titleMedium)
                            DiscoveryStatusTag(probe.status)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(probe.summary, style = MaterialTheme.typography.bodyMedium)
                        Text(
                            "${probe.accessLevelUsed.name} • ${probe.durationMs}ms",
                            style = MonoTextStyle,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            DashboardSection.COMPONENTS -> {
                items(session.components, key = { it.id }) { comp ->
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(comp.name, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                            EpistemicBadge(comp.epistemicLevel)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Role=${comp.role} • Partition=${comp.partition} • Status=${comp.discoveryStatus}",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(Modifier.height(6.dp))
                        MonoCodeBlock(
                            comp.location + if (comp.interfaces.isNotEmpty()) {
                                "\n" + comp.interfaces.joinToString("\n")
                            } else ""
                        )
                    }
                }
            }

            DashboardSection.DEPENDENCIES -> {
                item {
                    DependencyGraphCanvas(
                        components = session.components,
                        links = session.dependencies
                    )
                }
                items(session.dependencies, key = { it.id }) { link ->
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(link.relationType, style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
                            EpistemicBadge(link.epistemicLevel)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(link.notes, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }

            DashboardSection.TIMELINE -> {
                val live = session.liveTrace
                if (live == null) {
                    item {
                        LabCard(modifier = Modifier.fillMaxWidth()) {
                            Text("Phase 2 Live Trace not recorded yet. Tap '${strings.openEnrollment}' to observe real enrollment.", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                } else {
                    item {
                        LabCard(modifier = Modifier.fillMaxWidth()) {
                            Text("Duration: ${live.durationMs}ms • Sources: ${live.observedSources.size}", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(4.dp))
                            Text("Post-return Biometric Check: ${live.enrollmentReturnedWithBiometricCheck}", style = MonoTextStyle)
                        }
                    }
                    items(live.events, key = { it.id }) { evt ->
                        LabCard(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text("+${evt.relativeMs}ms  ${evt.type.name}", style = MaterialTheme.typography.labelLarge)
                                StatusTag(evt.confidence.name, sem.correlated)
                            }
                            Spacer(Modifier.height(4.dp))
                            Text("${evt.source} • ${evt.observationType.name}", style = MaterialTheme.typography.bodyMedium)
                            Spacer(Modifier.height(4.dp))
                            MonoCodeBlock(evt.data)
                        }
                    }
                }
            }

            DashboardSection.EVIDENCE -> {
                val proved = session.evidence.filter { it.epistemicLevel == EpistemicLevel.PROVED }
                items(proved.take(120), key = { it.id }) { ev ->
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(ev.id, style = MonoTextStyle)
                            EpistemicBadge(ev.epistemicLevel)
                        }
                        Text("${ev.resourceType} (${ev.accessLevel})", style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(4.dp))
                        MonoCodeBlock(ev.observedValue)
                    }
                }
            }

            DashboardSection.ANOMALIES -> {
                if (session.anomalies.isEmpty()) {
                    item {
                        LabCard(modifier = Modifier.fillMaxWidth()) {
                            Text("No proved anomalies detected in current observations.", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                } else {
                    items(session.anomalies, key = { it.id }) { anom ->
                        LabCard(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(anom.title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                                StatusTag(anom.severity.name, sem.critical)
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(anom.description, style = MaterialTheme.typography.bodyMedium)
                            if (anom.possibleCauses.isNotEmpty()) {
                                Spacer(Modifier.height(6.dp))
                                MonoCodeBlock("Causes:\n- " + anom.possibleCauses.joinToString("\n- "))
                            }
                        }
                    }
                }
            }

            DashboardSection.CORRELATIONS -> {
                items(session.correlations, key = { it.id }) { corr ->
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(corr.title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                            EpistemicBadge(corr.epistemicLevel)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text("Expected: ${corr.expectedChain}", style = MaterialTheme.typography.bodyMedium)
                        Text("Observed: ${corr.observedBehavior}", style = MonoTextStyle)
                        corr.unverifiableReason?.let {
                            Text("Limit: $it", style = MaterialTheme.typography.bodyMedium, color = sem.hypothesis)
                        }
                    }
                }
            }

            DashboardSection.HYPOTHESES -> {
                items(session.hypotheses, key = { it.id }) { hyp ->
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(hyp.statement, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                            EpistemicBadge(EpistemicLevel.HYPOTHESIS)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(hyp.rationale, style = MaterialTheme.typography.bodyMedium)
                        if (hyp.missingData.isNotEmpty()) {
                            Spacer(Modifier.height(4.dp))
                            MonoCodeBlock("Missing: " + hyp.missingData.joinToString(" | "))
                        }
                    }
                }
            }

            DashboardSection.INACCESSIBLE -> {
                val restricted = session.evidence.filter { it.epistemicLevel == EpistemicLevel.INACCESSIBLE }
                if (restricted.isEmpty()) {
                    item {
                        LabCard(modifier = Modifier.fillMaxWidth()) {
                            Text("All executed probes returned accessible observations.", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                } else {
                    items(restricted, key = { it.id }) { ev ->
                        LabCard(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(ev.source, style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
                                EpistemicBadge(EpistemicLevel.INACCESSIBLE)
                            }
                            Spacer(Modifier.height(4.dp))
                            MonoCodeBlock(ev.observedValue)
                        }
                    }
                }
            }

            DashboardSection.SYNTHESIS -> {
                item {
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Text("Diagnostic Synthesis", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(6.dp))
                        Text(
                            "Components=${session.components.size} • Proved=${session.evidence.count { it.epistemicLevel == EpistemicLevel.PROVED }} • Anomalies=${session.anomalies.size} • GSI Solutions=${session.solutions.size}",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(Modifier.height(10.dp))
                        if (isFirebaseAiAvailable) {
                            Button(
                                onClick = onRequestAiConsent,
                                enabled = aiState !is AiUiState.Loading,
                                modifier = Modifier.fillMaxWidth().minimumInteractiveComponentSize()
                            ) {
                                Icon(Icons.Filled.Psychology, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text(strings.analyzeWithAi)
                            }
                        } else {
                            Text(strings.aiDisabledOffline, style = MaterialTheme.typography.bodyMedium, color = sem.inaccessible)
                        }
                        if (aiState is AiUiState.Loading) {
                            Spacer(Modifier.height(8.dp))
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        }
                        if (aiState is AiUiState.Error) {
                            Spacer(Modifier.height(8.dp))
                            Text(aiState.message, color = sem.critical, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }

                session.aiAnalysis?.let { ai ->
                    item {
                        LabCard(modifier = Modifier.fillMaxWidth()) {
                            Text("AI Advisor (${ai.modelName} • Thinking=${ai.thinkingLevel})", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(6.dp))
                            Text(ai.summary, style = MaterialTheme.typography.bodyLarge)
                            if (ai.investigationLeads.isNotEmpty()) {
                                Spacer(Modifier.height(8.dp))
                                MonoCodeBlock("Leads:\n- " + ai.investigationLeads.joinToString("\n- "))
                            }
                            Spacer(Modifier.height(6.dp))
                            Text(ai.disclaimer, style = MaterialTheme.typography.labelSmall, color = sem.hypothesis)
                        }
                    }
                }
            }
        }
    }
}
