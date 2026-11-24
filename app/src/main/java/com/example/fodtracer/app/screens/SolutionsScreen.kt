package com.example.fodtracer.app.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.fodtracer.app.components.LabCard
import com.example.fodtracer.app.components.MonoCodeBlock
import com.example.fodtracer.app.components.StatusTag
import com.example.fodtracer.app.i18n.LocalFodStrings
import com.example.fodtracer.domain.models.*
import com.example.ui.theme.LocalSemanticColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SolutionsScreen(
    proposals: List<SolutionProposal>,
    selectedCategory: SolutionCategory?,
    activeSession: DiagnosticSession?,
    latestComparison: ComparisonReport?,
    isAiRunning: Boolean,
    isFirebaseAiAvailable: Boolean,
    aiError: String?,
    onBack: () -> Unit,
    onFilterCategory: (SolutionCategory?) -> Unit,
    onTriggerAiSynthesis: () -> Unit,
    onClearAiError: () -> Unit,
    modifier: Modifier = Modifier
) {
    val strings = LocalFodStrings.current
    val sem = LocalSemanticColors.current
    var showConsent by remember { mutableStateOf(false) }

    if (showConsent) {
        AlertDialog(
            onDismissRequest = { showConsent = false },
            title = { Text(strings.aiConsentTitle) },
            text = { Text(strings.aiConsentBody) },
            confirmButton = {
                Button(onClick = {
                    showConsent = false
                    onTriggerAiSynthesis()
                }) { Text(strings.aiConsentConfirm) }
            },
            dismissButton = {
                TextButton(onClick = { showConsent = false }) { Text(strings.aiConsentCancel) }
            }
        )
    }

    val filtered = remember(proposals, selectedCategory) {
        if (selectedCategory == null) proposals else proposals.filter { it.category == selectedCategory }
    }

    val aiAnalysis = activeSession?.aiAnalysis ?: latestComparison?.aiAnalysis

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(strings.featureSolutionsAi, style = MaterialTheme.typography.titleLarge) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.minimumInteractiveComponentSize()) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = strings.back)
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
            item {
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChip(
                        selected = selectedCategory == null,
                        onClick = { onFilterCategory(null) },
                        label = { Text("${strings.allCategories} (${proposals.size})") }
                    )
                    FilterChip(
                        selected = selectedCategory == SolutionCategory.GSI_ONLY_CONFIGURATION,
                        onClick = { onFilterCategory(SolutionCategory.GSI_ONLY_CONFIGURATION) },
                        label = { Text(strings.catGsiConfig) }
                    )
                    FilterChip(
                        selected = selectedCategory == SolutionCategory.GSI_ONLY_RUNTIME,
                        onClick = { onFilterCategory(SolutionCategory.GSI_ONLY_RUNTIME) },
                        label = { Text(strings.catGsiRuntime) }
                    )
                    FilterChip(
                        selected = selectedCategory == SolutionCategory.OUTSIDE_GSI_SCOPE,
                        onClick = { onFilterCategory(SolutionCategory.OUTSIDE_GSI_SCOPE) },
                        label = { Text(strings.catOutsideGsi) }
                    )
                }
            }

            item {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Text(strings.aiSectionTitle, style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(6.dp))
                    if (isFirebaseAiAvailable) {
                        Button(
                            onClick = { showConsent = true },
                            enabled = !isAiRunning && (activeSession != null || latestComparison != null),
                            modifier = Modifier.fillMaxWidth().minimumInteractiveComponentSize().testTag("solutions_ai_button")
                        ) {
                            Icon(Icons.Filled.Psychology, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(strings.analyzeWithAi)
                        }
                    } else {
                        Text(strings.aiDisabledOffline, style = MaterialTheme.typography.bodyMedium, color = sem.inaccessible)
                    }
                    if (isAiRunning) {
                        Spacer(Modifier.height(8.dp))
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                    aiError?.let { err ->
                        Spacer(Modifier.height(6.dp))
                        Text(err, color = sem.critical, style = MaterialTheme.typography.bodyMedium)
                        TextButton(onClick = onClearAiError) { Text("OK") }
                    }
                }
            }

            aiAnalysis?.let { ai ->
                item {
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Text("AI (${ai.modelName} • ${ai.thinkingLevel})", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(6.dp))
                        Text(ai.summary, style = MaterialTheme.typography.bodyLarge)
                        if (ai.gsiScopeLimitations.isNotEmpty()) {
                            Spacer(Modifier.height(6.dp))
                            MonoCodeBlock("GSI Scope:\n- " + ai.gsiScopeLimitations.joinToString("\n- "))
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(ai.disclaimer, style = MaterialTheme.typography.labelSmall, color = sem.hypothesis)
                    }
                }
            }

            if (filtered.isEmpty()) {
                item {
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Text("No deterministic solution proposals match this filter yet.", style = MaterialTheme.typography.bodyMedium)
                    }
                }
            } else {
                items(filtered, key = { it.id }) { prop ->
                    val catColor = when (prop.category) {
                        SolutionCategory.GSI_ONLY_CONFIGURATION -> sem.proved
                        SolutionCategory.GSI_ONLY_RUNTIME -> sem.correlated
                        SolutionCategory.OUTSIDE_GSI_SCOPE -> sem.critical
                    }
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            StatusTag(prop.category.name, catColor)
                            StatusTag(prop.feasibility.name, MaterialTheme.colorScheme.primary)
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(prop.problemIdentified, style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(4.dp))
                        Text(prop.probableCause, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(6.dp))
                        MonoCodeBlock(
                            "Component: ${prop.componentName} (${prop.partitionOrigin})\n" +
                                "Location: ${prop.componentLocation}\n" +
                                "Prerequisites: ${prop.technicalPrerequisites.joinToString("; ")}\n" +
                                "Risks: ${prop.compatibilityRisks.joinToString("; ")}\n" +
                                "Validation: ${prop.validationMethod}"
                        )
                    }
                }
            }
        }
    }
}
