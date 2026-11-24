package com.example.fodtracer.app.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FileOpen
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
import com.example.fodtracer.domain.models.DiagnosticSession
import com.example.ui.theme.MonoTextStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ArchivesScreen(
    sessions: List<DiagnosticSession>,
    publicExports: List<String>,
    anonymizeDefault: Boolean,
    feedbackMessage: String?,
    onBack: () -> Unit,
    onExportSession: (DiagnosticSession, Boolean, Uri?) -> Unit,
    onExportMarkdown: (DiagnosticSession, Boolean, Uri?) -> Unit,
    onImportZip: (Uri) -> Unit,
    onOpenSession: (String) -> Unit,
    onDeleteSession: (String) -> Unit,
    onClearFeedback: () -> Unit,
    modifier: Modifier = Modifier
) {
    val strings = LocalFodStrings.current
    var anonymizeExport by remember(anonymizeDefault) { mutableStateOf(anonymizeDefault) }
    var pendingExportSession by remember { mutableStateOf<DiagnosticSession?>(null) }
    var pendingMdExportSession by remember { mutableStateOf<DiagnosticSession?>(null) }

    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let(onImportZip)
    }

    val createZipLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        val sess = pendingExportSession
        pendingExportSession = null
        if (uri != null && sess != null) {
            onExportSession(sess, anonymizeExport, uri)
        }
    }

    val createMdLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/markdown")
    ) { uri ->
        val sess = pendingMdExportSession
        pendingMdExportSession = null
        if (uri != null && sess != null) {
            onExportMarkdown(sess, anonymizeExport, uri)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(strings.featureArchives, style = MaterialTheme.typography.titleLarge) },
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
            feedbackMessage?.let { msg ->
                item {
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                            Text(msg, style = MonoTextStyle, modifier = Modifier.weight(1f))
                            TextButton(onClick = onClearFeedback) { Text("OK") }
                        }
                    }
                }
            }

            item {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(strings.anonymizeOnExport, style = MaterialTheme.typography.bodyLarge)
                        Switch(
                            checked = anonymizeExport,
                            onCheckedChange = { anonymizeExport = it }
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = {
                            importLauncher.launch(arrayOf("application/zip", "application/octet-stream", "*/*"))
                        },
                        modifier = Modifier.fillMaxWidth().minimumInteractiveComponentSize().testTag("import_zip_button")
                    ) {
                        Icon(Icons.Filled.FileOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(strings.importZip)
                    }
                }
            }

            items(sessions, key = { it.sessionId }) { session ->
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(session.label, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                        StatusTag(session.environment.detectedRomType.name, MaterialTheme.colorScheme.primary)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text("${session.sessionId} • v${session.schemaVersion} • ${session.anomalies.size} anom • ${session.disassembledArtifacts.size} disasm", style = MonoTextStyle)
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = { onOpenSession(session.sessionId) },
                            modifier = Modifier.weight(1f).minimumInteractiveComponentSize()
                        ) {
                            Text(strings.openInDashboard, maxLines = 1)
                        }
                        OutlinedButton(
                            onClick = { onExportSession(session, anonymizeExport, null) },
                            modifier = Modifier.weight(1f).minimumInteractiveComponentSize()
                        ) {
                            Icon(Icons.Filled.Archive, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(strings.exportZip, maxLines = 1)
                        }
                        IconButton(
                            onClick = {
                                pendingExportSession = session
                                createZipLauncher.launch("${session.sessionId}.fodtracer.zip")
                            },
                            modifier = Modifier.minimumInteractiveComponentSize()
                        ) {
                            Icon(Icons.Filled.FileOpen, contentDescription = "SAF ZIP Export")
                        }
                        IconButton(
                            onClick = { onDeleteSession(session.sessionId) },
                            modifier = Modifier.minimumInteractiveComponentSize()
                        ) {
                            Icon(Icons.Filled.DeleteOutline, contentDescription = strings.deleteLabel)
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilledTonalButton(
                            onClick = { onExportMarkdown(session, anonymizeExport, null) },
                            modifier = Modifier
                                .weight(1f)
                                .minimumInteractiveComponentSize()
                                .testTag("export_md_archive_${session.sessionId}")
                        ) {
                            Icon(Icons.Filled.Description, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(strings.exportMd, maxLines = 1)
                        }
                        OutlinedButton(
                            onClick = {
                                pendingMdExportSession = session
                                createMdLauncher.launch("${session.sessionId}.md")
                            },
                            modifier = Modifier
                                .weight(1f)
                                .minimumInteractiveComponentSize()
                                .testTag("export_md_saf_archive_${session.sessionId}")
                        ) {
                            Icon(Icons.Filled.FileOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(strings.exportMdSaf, maxLines = 1)
                        }
                    }
                }
            }

            if (publicExports.isNotEmpty()) {
                item {
                    LabCard(modifier = Modifier.fillMaxWidth()) {
                        Text("ZIP / MD Exports (${publicExports.size})", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(6.dp))
                        MonoCodeBlock(publicExports.joinToString("\n"))
                    }
                }
            }
        }
    }
}
