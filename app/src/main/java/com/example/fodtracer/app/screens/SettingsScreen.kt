package com.example.fodtracer.app.screens

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.fodtracer.app.components.LabCard
import com.example.fodtracer.app.components.MonoCodeBlock
import com.example.fodtracer.app.components.StatusTag
import com.example.fodtracer.app.i18n.LocalFodStrings
import com.example.fodtracer.domain.interfaces.PrivilegeSnapshot
import com.example.fodtracer.domain.interfaces.ShellLogEntry
import com.example.fodtracer.domain.models.LanguagePreference
import com.example.fodtracer.domain.models.RootState
import com.example.fodtracer.domain.models.SeLinuxMode
import com.example.fodtracer.domain.models.ThemePreference
import com.example.fodtracer.system.permissions.StorageAndPermissionHelper
import com.example.ui.theme.LocalSemanticColors
import com.example.ui.theme.MonoTextStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    privilegeSnapshot: PrivilegeSnapshot,
    shellLogs: List<ShellLogEntry>,
    themePreference: ThemePreference,
    languagePreference: LanguagePreference,
    aiEnabled: Boolean,
    anonymizeByDefault: Boolean,
    isFirebaseAiConfigured: Boolean,
    onBack: () -> Unit,
    onRefreshPrivileges: () -> Unit,
    onRequestAndTestRoot: () -> Unit,
    onSelectTheme: (ThemePreference) -> Unit,
    onSelectLanguage: (LanguagePreference) -> Unit,
    onToggleAi: (Boolean) -> Unit,
    onToggleAnonymize: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    val strings = LocalFodStrings.current
    val context = LocalContext.current
    val sem = LocalSemanticColors.current

    val allFilesLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        onRefreshPrivileges()
    }

    val notifLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) {
        onRefreshPrivileges()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(strings.settings, style = MaterialTheme.typography.titleLarge) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.minimumInteractiveComponentSize()) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = strings.back)
                    }
                },
                actions = {
                    IconButton(onClick = onRefreshPrivileges, modifier = Modifier.minimumInteractiveComponentSize()) {
                        Icon(Icons.Filled.Refresh, contentDescription = strings.refreshStatusAction)
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
            // ROOT Card
            item {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Icon(Icons.Filled.AdminPanelSettings, contentDescription = null)
                            Text("ROOT (su)", style = MaterialTheme.typography.titleMedium)
                        }
                        val rootColor = when (privilegeSnapshot.rootState) {
                            RootState.GRANTED_VERIFIED -> sem.proved
                            RootState.AVAILABLE_NOT_GRANTED -> sem.hypothesis
                            RootState.DENIED -> sem.critical
                            else -> sem.inaccessible
                        }
                        StatusTag(privilegeSnapshot.rootState.name, rootColor)
                    }
                    Spacer(Modifier.height(8.dp))
                    MonoCodeBlock(
                        "su binary: ${privilegeSnapshot.suBinaryPath ?: "not detected (trying PATH su)"}\n" +
                            "Manager hint: ${privilegeSnapshot.rootProviderHint ?: "none"}\n" +
                            "Verified UID: ${privilegeSnapshot.rootUidInfo ?: "unverified"}" +
                            (privilegeSnapshot.rootDiagnosticNote?.let { "\nNote: $it" } ?: "")
                    )
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = onRequestAndTestRoot,
                        modifier = Modifier.fillMaxWidth().minimumInteractiveComponentSize().testTag("test_root_button")
                    ) {
                        Text(strings.testRootAction)
                    }
                }
            }

            // SELinux Read-Only Card
            item {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Icon(Icons.Filled.Security, contentDescription = null)
                            Text("SELinux", style = MaterialTheme.typography.titleMedium)
                        }
                        StatusTag(
                            privilegeSnapshot.seLinuxMode.name,
                            if (privilegeSnapshot.seLinuxMode == SeLinuxMode.ENFORCING) MaterialTheme.colorScheme.primary else sem.hypothesis
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(strings.seLinuxNotice, style = MaterialTheme.typography.bodyMedium)
                    privilegeSnapshot.seLinuxContext?.let {
                        Spacer(Modifier.height(4.dp))
                        MonoCodeBlock("Context: $it")
                    }
                }
            }

            // Storage & Permissions Card
            item {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Icon(Icons.Filled.FolderSpecial, contentDescription = null)
                            Text(strings.storageLabel, style = MaterialTheme.typography.titleMedium)
                        }
                        StatusTag(
                            if (privilegeSnapshot.publicFodDirWritable) "WRITABLE" else "PRIVATE/SAF",
                            if (privilegeSnapshot.publicFodDirWritable) sem.proved else MaterialTheme.colorScheme.primary
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    MonoCodeBlock(
                        "Public path: ${privilegeSnapshot.publicFodDirPath}\n" +
                            "All files access: ${privilegeSnapshot.manageExternalStorageGranted}\n" +
                            "Notifications: ${privilegeSnapshot.postNotificationsGranted}"
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = {
                                runCatching {
                                    allFilesLauncher.launch(StorageAndPermissionHelper.buildManageAllFilesIntent(context))
                                }
                            },
                            modifier = Modifier.weight(1f).minimumInteractiveComponentSize()
                        ) {
                            Text(strings.grantStorageAction, maxLines = 1)
                        }
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            OutlinedButton(
                                onClick = { notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) },
                                modifier = Modifier.weight(1f).minimumInteractiveComponentSize()
                            ) {
                                Text(strings.grantNotificationsAction, maxLines = 1)
                            }
                        }
                    }
                }
            }

            // Theme & Language Card
            item {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Text(strings.themeTitle, style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(
                            selected = themePreference == ThemePreference.LIGHT,
                            onClick = { onSelectTheme(ThemePreference.LIGHT) },
                            label = { Text(strings.themeLight) },
                            modifier = Modifier.testTag("theme_light_chip")
                        )
                        FilterChip(
                            selected = themePreference == ThemePreference.DARK,
                            onClick = { onSelectTheme(ThemePreference.DARK) },
                            label = { Text(strings.themeDark) },
                            modifier = Modifier.testTag("theme_dark_chip")
                        )
                        FilterChip(
                            selected = themePreference == ThemePreference.SYSTEM,
                            onClick = { onSelectTheme(ThemePreference.SYSTEM) },
                            label = { Text(strings.themeSystem) }
                        )
                    }

                    Spacer(Modifier.height(14.dp))
                    Text(strings.languageTitle, style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(
                            selected = languagePreference == LanguagePreference.SYSTEM,
                            onClick = { onSelectLanguage(LanguagePreference.SYSTEM) },
                            label = { Text(strings.langSystem) }
                        )
                        FilterChip(
                            selected = languagePreference == LanguagePreference.FRENCH,
                            onClick = { onSelectLanguage(LanguagePreference.FRENCH) },
                            label = { Text(strings.langFrench) }
                        )
                        FilterChip(
                            selected = languagePreference == LanguagePreference.ENGLISH,
                            onClick = { onSelectLanguage(LanguagePreference.ENGLISH) },
                            label = { Text(strings.langEnglish) }
                        )
                    }
                }
            }

            // AI & Anonymization Defaults
            item {
                LabCard(modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(strings.aiSectionTitle, style = MaterialTheme.typography.titleMedium)
                            Text(
                                if (isFirebaseAiConfigured) "Firebase AI Logic ready (gemini-3.8-flash)" else strings.aiDisabledOffline,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(checked = aiEnabled, onCheckedChange = onToggleAi)
                    }
                    Spacer(Modifier.height(10.dp))
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Text(strings.anonymizeOnExport, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                        Switch(checked = anonymizeByDefault, onCheckedChange = onToggleAnonymize)
                    }
                }
            }

            // Shell Execution Audit Log
            if (shellLogs.isNotEmpty()) {
                item {
                    Text(strings.shellAuditTitle, style = MaterialTheme.typography.titleMedium)
                }
                items(shellLogs.take(20)) { log ->
                    MonoCodeBlock(
                        "[${if (log.usedRoot) "su" else "sh"}] ${log.commandDisplay} -> exit=${log.exitCode} bytes=${log.outputBytes}" +
                            if (log.denied) " (DENIED)" else if (log.timedOut) " (TIMEOUT)" else ""
                    )
                }
            }
        }
    }
}
