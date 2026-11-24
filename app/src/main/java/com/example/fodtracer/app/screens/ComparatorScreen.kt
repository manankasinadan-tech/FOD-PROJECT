package com.example.fodtracer.app.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.fodtracer.app.components.LabCard
import com.example.fodtracer.app.components.MonoCodeBlock
import com.example.fodtracer.app.components.StatusTag
import com.example.fodtracer.app.i18n.LocalFodStrings
import com.example.fodtracer.domain.models.*
import com.example.ui.theme.LocalSemanticColors
import com.example.ui.theme.MonoTextStyle

private enum class ComparatorTab { STRUCTURAL, BEHAVIORAL, ANOMALIES }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ComparatorScreen(
    archiveA: DiagnosticSession?,
    archiveB: DiagnosticSession?,
    report: ComparisonReport?,
    savedSessions: List<DiagnosticSession>,
    isComparing: Boolean,
    isAiRunning: Boolean,
    isFirebaseAiAvailable: Boolean,
    errorMessage: String?,
    onBack: () -> Unit,
    onImportA: (Uri) -> Unit,
    onImportB: (Uri) -> Unit,
    onSelectLocalA: (DiagnosticSession) -> Unit,
    onSelectLocalB: (DiagnosticSession) -> Unit,
    onLoadDemoPair: () -> Unit,
    onRunComparison: () -> Unit,
    onRunAiOnComparison: () -> Unit,
    onClearError: () -> Unit,
    modifier: Modifier = Modifier
) {
    val strings = LocalFodStrings.current
    val sem = LocalSemanticColors.current
    var selectedTab by remember { mutableStateOf(ComparatorTab.STRUCTURAL) }
    var pickingForA by remember { mutableStateOf(true) }
    var showLocalDialogForA by remember { mutableStateOf<Boolean?>(null) }

    val zipPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let {
            if (pickingForA) onImportA(it) else onImportB(it)
        }
    }

    showLocalDialogForA?.let { isForA ->
        AlertDialog(
            onDismissRequest = { showLocalDialogForA = null },
            title = { Text(strings.useLocalSession) },
            text = {
                LazyColumn(modifier = Modifier.heightIn(max = 280.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(savedSessions, key = { it.sessionId }) { sess ->
                        LabCard(
                            onClick = {
                                if (isForA) onSelectLocalA(sess) else onSelectLocalB(sess)
                                showLocalDialogForA = null
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(sess.label, style = MaterialTheme.typography.labelLarge)
                            Text(sess.sessionId, style = MonoTextStyle)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showLocalDialogForA = null }) { Text(strings.aiConsentCancel) }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(strings.featureComparator, style = MaterialTheme.typography.titleLarge) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.minimumInteractiveComponentSize()) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = strings.back)
                    }
                },
                actions = {
                    TextButton(onClick = onLoadDemoPair, modifier = Modifier.testTag("load_demo_pair_button")) {
                        Text(strings.loadDemoPair)
                    }
                }
            )
        },
        modifier = modifier
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(bottom = 24.dp)
        ) {
            errorMessage?.let { err ->
                item {
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                            Text(err, color = sem.critical, modifier = Modifier.weight(1f))
                            TextButton(onClick = onClearError) { Text("OK") }
                        }
                    }
                }
            }

            item {
                ArchiveSlotCard(
                    title = strings.archiveAPlaceholder,
                    session = archiveA,
                    importLabel = strings.importZip,
                    localLabel = strings.useLocalSession,
                    hasLocal = savedSessions.isNotEmpty(),
                    onImportZip = {
                        pickingForA = true
                        zipPicker.launch(arrayOf("application/zip", "application/octet-stream", "*/*"))
                    },
                    onPickLocal = { showLocalDialogForA = true }
                )
            }

            item {
                ArchiveSlotCard(
                    title = strings.archiveBPlaceholder,
                    session = archiveB,
                    importLabel = strings.importZip,
                    localLabel = strings.useLocalSession,
                    hasLocal = savedSessions.isNotEmpty(),
                    onImportZip = {
                        pickingForA = false
                        zipPicker.launch(arrayOf("application/zip", "application/octet-stream", "*/*"))
                    },
                    onPickLocal = { showLocalDialogForA = false }
                )
            }

            item {
                Button(
                    onClick = onRunComparison,
                    enabled = archiveA != null && archiveB != null && !isComparing,
                    modifier = Modifier.fillMaxWidth().minimumInteractiveComponentSize().testTag("run_compare_button")
                ) {
                    Icon(Icons.Filled.CompareArrows, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(strings.runComparison)
                }
            }

            report?.let { cmp ->
                item {
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(strings.compatibilityTitle, style = MaterialTheme.typography.titleMedium)
                            StatusTag(
                                text = "HW ${cmp.compatibility.hardwareMatchScore}%",
                                accent = if (cmp.compatibility.isComparable) sem.proved else sem.critical
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                        Text(cmp.summary, style = MaterialTheme.typography.bodyMedium)
                        if (cmp.compatibility.warnings.isNotEmpty()) {
                            Spacer(Modifier.height(6.dp))
                            MonoCodeBlock(cmp.compatibility.warnings.joinToString("\n"))
                        }
                        if (isFirebaseAiAvailable) {
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(
                                onClick = onRunAiOnComparison,
                                enabled = !isAiRunning,
                                modifier = Modifier.fillMaxWidth().minimumInteractiveComponentSize()
                            ) {
                                Icon(Icons.Filled.Psychology, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text(strings.analyzeWithAi)
                            }
                        }
                    }
                }

                cmp.aiAnalysis?.let { ai ->
                    item {
                        LabCard(modifier = Modifier.fillMaxWidth()) {
                            Text("AI Comparison Insight (${ai.modelName})", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(4.dp))
                            Text(ai.summary, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }

                item {
                    Row(
                        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        FilterChip(
                            selected = selectedTab == ComparatorTab.STRUCTURAL,
                            onClick = { selectedTab = ComparatorTab.STRUCTURAL },
                            label = { Text("${strings.structuralDiffs} (${cmp.structuralDiffs.size})") }
                        )
                        FilterChip(
                            selected = selectedTab == ComparatorTab.BEHAVIORAL,
                            onClick = { selectedTab = ComparatorTab.BEHAVIORAL },
                            label = { Text("${strings.behavioralTimeline} (${cmp.behavioralDiffs.size})") }
                        )
                        FilterChip(
                            selected = selectedTab == ComparatorTab.ANOMALIES,
                            onClick = { selectedTab = ComparatorTab.ANOMALIES },
                            label = { Text("${strings.anomaliesHypotheses} (${cmp.regressionHypotheses.size})") }
                        )
                    }
                }

                when (selectedTab) {
                    ComparatorTab.STRUCTURAL -> {
                        items(cmp.structuralDiffs, key = { it.id }) { diff ->
                            val accent = when (diff.impact) {
                                DiffImpact.CRITICAL -> sem.critical
                                DiffImpact.BENIGN -> sem.proved
                                DiffImpact.INFORMATIONAL -> MaterialTheme.colorScheme.primary
                            }
                            LabCard(modifier = Modifier.fillMaxWidth()) {
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("${diff.domain.name}: ${diff.key}", style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
                                    StatusTag(diff.classification.name, accent)
                                }
                                Spacer(Modifier.height(4.dp))
                                Text(diff.rationale, style = MaterialTheme.typography.bodyMedium)
                                Spacer(Modifier.height(4.dp))
                                MonoCodeBlock("ROM A: ${diff.valueInRomA ?: "—"}\nGSI B: ${diff.valueInGsiB ?: "—"}")
                            }
                        }
                    }
                    ComparatorTab.BEHAVIORAL -> {
                        items(cmp.behavioralDiffs, key = { it.id }) { diff ->
                            val accent = when (diff.impact) {
                                DiffImpact.CRITICAL -> sem.critical
                                DiffImpact.BENIGN -> sem.proved
                                DiffImpact.INFORMATIONAL -> MaterialTheme.colorScheme.primary
                            }
                            LabCard(modifier = Modifier.fillMaxWidth()) {
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text(diff.stepName, style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
                                    StatusTag(diff.classification.name, accent)
                                }
                                Spacer(Modifier.height(4.dp))
                                Text(diff.observation, style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "ROM: ${diff.romRelativeMs ?: "?"}ms | GSI: ${diff.gsiRelativeMs ?: "?"}ms | Delta: ${diff.latencyDeltaMs ?: "?"}ms",
                                    style = MonoTextStyle
                                )
                            }
                        }
                    }
                    ComparatorTab.ANOMALIES -> {
                        items(cmp.regressionHypotheses, key = { it.id }) { hyp ->
                            LabCard(modifier = Modifier.fillMaxWidth()) {
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text(hyp.statement, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                                    StatusTag(hyp.confidence.name, sem.hypothesis)
                                }
                                Spacer(Modifier.height(4.dp))
                                Text(hyp.rationale, style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ArchiveSlotCard(
    title: String,
    session: DiagnosticSession?,
    importLabel: String,
    localLabel: String,
    hasLocal: Boolean,
    onImportZip: () -> Unit,
    onPickLocal: () -> Unit
) {
    LabCard(modifier = Modifier.fillMaxWidth()) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        if (session != null) {
            MonoCodeBlock("${session.label}\n${session.sessionId} • ${session.environment.detectedRomType}")
        } else {
            Text("—", style = MonoTextStyle, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onImportZip, modifier = Modifier.weight(1f).minimumInteractiveComponentSize()) {
                Icon(Icons.Filled.FolderOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text(importLabel)
            }
            OutlinedButton(onClick = onPickLocal, enabled = hasLocal, modifier = Modifier.weight(1f).minimumInteractiveComponentSize()) {
                Text(localLabel)
            }
        }
    }
}
