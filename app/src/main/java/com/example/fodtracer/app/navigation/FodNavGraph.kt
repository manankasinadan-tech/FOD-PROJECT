package com.example.fodtracer.app.navigation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.example.fodtracer.app.i18n.LocalFodStrings
import com.example.fodtracer.app.i18n.resolveFodStrings
import com.example.fodtracer.app.screens.ArchivesScreen
import com.example.fodtracer.app.screens.ComparatorScreen
import com.example.fodtracer.app.screens.DiagnosticScreen
import com.example.fodtracer.app.screens.HomeScreen
import com.example.fodtracer.app.screens.SettingsScreen
import com.example.fodtracer.app.screens.SolutionsScreen
import com.example.fodtracer.presentation.AppContainer
import com.example.fodtracer.presentation.archives.ArchivesViewModel
import com.example.fodtracer.presentation.comparator.ComparatorViewModel
import com.example.fodtracer.presentation.diagnostic.DiagnosticViewModel
import com.example.fodtracer.presentation.settings.SettingsViewModel
import com.example.fodtracer.presentation.solutions.SolutionsViewModel
import com.example.ui.theme.FodTracerTheme
import kotlinx.serialization.Serializable

@Serializable
data object HomeRoute

@Serializable
data object DiagnosticRoute

@Serializable
data object ComparatorRoute

@Serializable
data object SolutionsRoute

@Serializable
data object ArchivesRoute

@Serializable
data object SettingsRoute

@Composable
fun FodTracerApp(container: AppContainer) {
    val settingsVm: SettingsViewModel = viewModel(factory = SettingsViewModel.Factory(container))
    val diagnosticVm: DiagnosticViewModel = viewModel(factory = DiagnosticViewModel.Factory(container))
    val comparatorVm: ComparatorViewModel = viewModel(factory = ComparatorViewModel.Factory(container))
    val solutionsVm: SolutionsViewModel = viewModel(factory = SolutionsViewModel.Factory(container))
    val archivesVm: ArchivesViewModel = viewModel(factory = ArchivesViewModel.Factory(container))

    val themePref by settingsVm.themePreference.collectAsStateWithLifecycle()
    val languagePref by settingsVm.languagePreference.collectAsStateWithLifecycle()
    val privilegeSnapshot by settingsVm.privilegeSnapshot.collectAsStateWithLifecycle()
    val activeSession by diagnosticVm.activeSession.collectAsStateWithLifecycle()
    val savedSessions by archivesVm.sessions.collectAsStateWithLifecycle()
    val comparisons by container.diagnosticRepository.comparisons.collectAsStateWithLifecycle(initialValue = emptyList())

    val strings = resolveFodStrings(languagePref)
    val navController = rememberNavController()

    CompositionLocalProvider(LocalFodStrings provides strings) {
        FodTracerTheme(themePreference = themePref) {
            NavHost(
                navController = navController,
                startDestination = HomeRoute,
                modifier = Modifier.fillMaxSize()
            ) {
                composable<HomeRoute> {
                    Scaffold(contentWindowInsets = WindowInsets.safeDrawing) { innerPadding ->
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(innerPadding)
                        ) {
                            HomeScreen(
                                privilegeSnapshot = privilegeSnapshot,
                                activeSession = activeSession,
                                sessionCount = savedSessions.size,
                                comparisonCount = comparisons.size,
                                onOpenDiagnostic = { navController.navigate(DiagnosticRoute) },
                                onOpenComparator = { navController.navigate(ComparatorRoute) },
                                onOpenSolutions = { navController.navigate(SolutionsRoute) },
                                onOpenArchives = { navController.navigate(ArchivesRoute) },
                                onOpenSettings = { navController.navigate(SettingsRoute) }
                            )
                        }
                    }
                }

                composable<DiagnosticRoute> {
                    val coldState by diagnosticVm.coldState.collectAsStateWithLifecycle()
                    val liveProgress by diagnosticVm.liveProgress.collectAsStateWithLifecycle()
                    val selectedSection by diagnosticVm.selectedSection.collectAsStateWithLifecycle()
                    val aiState by diagnosticVm.aiState.collectAsStateWithLifecycle()
                    val showAiConsent by diagnosticVm.showAiConsentDialog.collectAsStateWithLifecycle()
                    val statusMessage by diagnosticVm.statusMessage.collectAsStateWithLifecycle()
                    val aiEnabled by settingsVm.aiEnabled.collectAsStateWithLifecycle()

                    DiagnosticScreen(
                        coldState = coldState,
                        activeSession = activeSession,
                        liveProgress = liveProgress,
                        selectedSection = selectedSection,
                        aiState = aiState,
                        showAiConsentDialog = showAiConsent,
                        isFirebaseAiAvailable = diagnosticVm.isFirebaseAiAvailable && aiEnabled,
                        statusMessage = statusMessage,
                        onBack = { navController.popBackStack() },
                        onSelectSection = diagnosticVm::selectSection,
                        onStartColdAnalysis = diagnosticVm::startColdAnalysis,
                        onStartLiveEnrollment = diagnosticVm::startLiveTracerAndBuildEnrollmentIntent,
                        onStopLiveTrace = diagnosticVm::stopLiveTracerAndCorrelate,
                        onRequestAiConsent = diagnosticVm::requestAiAnalysisConsent,
                        onDismissAiConsent = diagnosticVm::dismissAiConsent,
                        onConfirmAiAnalysis = diagnosticVm::confirmAndRunAiAnalysis,
                        onClearStatusMessage = diagnosticVm::clearStatusMessage
                    )
                }

                composable<ComparatorRoute> {
                    val archiveA by comparatorVm.archiveA.collectAsStateWithLifecycle()
                    val archiveB by comparatorVm.archiveB.collectAsStateWithLifecycle()
                    val report by comparatorVm.report.collectAsStateWithLifecycle()
                    val compSessions by comparatorVm.savedSessions.collectAsStateWithLifecycle()
                    val isComparing by comparatorVm.isComparing.collectAsStateWithLifecycle()
                    val isAiRunning by comparatorVm.isAiRunning.collectAsStateWithLifecycle()
                    val errorMsg by comparatorVm.errorMessage.collectAsStateWithLifecycle()
                    val aiEnabled by settingsVm.aiEnabled.collectAsStateWithLifecycle()

                    ComparatorScreen(
                        archiveA = archiveA,
                        archiveB = archiveB,
                        report = report,
                        savedSessions = compSessions,
                        isComparing = isComparing,
                        isAiRunning = isAiRunning,
                        isFirebaseAiAvailable = comparatorVm.isFirebaseAiAvailable && aiEnabled,
                        errorMessage = errorMsg,
                        onBack = { navController.popBackStack() },
                        onImportA = comparatorVm::importArchiveA,
                        onImportB = comparatorVm::importArchiveB,
                        onSelectLocalA = comparatorVm::selectLocalSessionAsA,
                        onSelectLocalB = comparatorVm::selectLocalSessionAsB,
                        onLoadDemoPair = comparatorVm::loadReferenceDemoPair,
                        onRunComparison = comparatorVm::runComparison,
                        onRunAiOnComparison = comparatorVm::runAiOnComparison,
                        onClearError = comparatorVm::clearError
                    )
                }

                composable<SolutionsRoute> {
                    val proposals by solutionsVm.allProposals.collectAsStateWithLifecycle()
                    val selectedCategory by solutionsVm.selectedCategory.collectAsStateWithLifecycle()
                    val solSession by solutionsVm.activeSession.collectAsStateWithLifecycle()
                    val latestComparison by solutionsVm.latestComparison.collectAsStateWithLifecycle()
                    val isAiRunning by solutionsVm.isAiRunning.collectAsStateWithLifecycle()
                    val aiError by solutionsVm.aiError.collectAsStateWithLifecycle()
                    val aiEnabled by settingsVm.aiEnabled.collectAsStateWithLifecycle()

                    SolutionsScreen(
                        proposals = proposals,
                        selectedCategory = selectedCategory,
                        activeSession = solSession,
                        latestComparison = latestComparison,
                        isAiRunning = isAiRunning,
                        isFirebaseAiAvailable = solutionsVm.isFirebaseAiAvailable && aiEnabled,
                        aiError = aiError,
                        onBack = { navController.popBackStack() },
                        onFilterCategory = solutionsVm::filterByCategory,
                        onTriggerAiSynthesis = solutionsVm::triggerAiSynthesis,
                        onClearAiError = solutionsVm::clearAiError
                    )
                }

                composable<ArchivesRoute> {
                    val publicExports by archivesVm.publicExports.collectAsStateWithLifecycle()
                    val anonymizeDefault by archivesVm.anonymizeByDefault.collectAsStateWithLifecycle()
                    val feedbackMessage by archivesVm.feedbackMessage.collectAsStateWithLifecycle()

                    ArchivesScreen(
                        sessions = savedSessions,
                        publicExports = publicExports,
                        anonymizeDefault = anonymizeDefault,
                        feedbackMessage = feedbackMessage,
                        onBack = { navController.popBackStack() },
                        onExportSession = archivesVm::exportSession,
                        onImportZip = { uri ->
                            archivesVm.importZipFromUri(uri) {
                                navController.navigate(DiagnosticRoute)
                            }
                        },
                        onOpenSession = { sessionId ->
                            archivesVm.openSession(sessionId) {
                                navController.navigate(DiagnosticRoute)
                            }
                        },
                        onDeleteSession = archivesVm::deleteSession,
                        onClearFeedback = archivesVm::clearFeedback
                    )
                }

                composable<SettingsRoute> {
                    val shellLogs by settingsVm.shellLogs.collectAsStateWithLifecycle()
                    val aiEnabled by settingsVm.aiEnabled.collectAsStateWithLifecycle()
                    val anonymizeDefault by settingsVm.anonymizeByDefault.collectAsStateWithLifecycle()

                    SettingsScreen(
                        privilegeSnapshot = privilegeSnapshot,
                        shellLogs = shellLogs,
                        themePreference = themePref,
                        languagePreference = languagePref,
                        aiEnabled = aiEnabled,
                        anonymizeByDefault = anonymizeDefault,
                        isFirebaseAiConfigured = settingsVm.isFirebaseAiConfigured,
                        onBack = { navController.popBackStack() },
                        onRefreshPrivileges = settingsVm::refreshPrivileges,
                        onRequestAndTestRoot = settingsVm::requestAndTestRoot,
                        onSelectTheme = settingsVm::setTheme,
                        onSelectLanguage = settingsVm::setLanguage,
                        onToggleAi = settingsVm::setAiEnabled,
                        onToggleAnonymize = settingsVm::setAnonymizeByDefault
                    )
                }
            }
        }
    }
}
