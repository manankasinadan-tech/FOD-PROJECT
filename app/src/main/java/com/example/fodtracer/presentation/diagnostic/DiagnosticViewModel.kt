package com.example.fodtracer.presentation.diagnostic

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.fodtracer.core.probe.ProbeExecutionProgress
import com.example.fodtracer.domain.interfaces.AiAdvisorService
import com.example.fodtracer.domain.interfaces.DiagnosticRepository
import com.example.fodtracer.domain.interfaces.PrivilegeManager
import com.example.fodtracer.domain.models.DiagnosticSession
import com.example.fodtracer.domain.models.ProbeDomain
import com.example.fodtracer.domain.usecases.FinalizeLiveTraceUseCase
import com.example.fodtracer.domain.usecases.RunColdDiagnosticUseCase
import com.example.fodtracer.system.biometrics.AndroidBiometricInspector
import com.example.fodtracer.workers.live.FodLiveTracerService
import com.example.fodtracer.workers.live.LiveTraceCoordinator
import com.example.fodtracer.workers.live.LiveTraceProgress
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

enum class DashboardSection {
    OVERVIEW,
    COMPONENTS,
    DEPENDENCIES,
    TIMELINE,
    EVIDENCE,
    ANOMALIES,
    CORRELATIONS,
    HYPOTHESES,
    INACCESSIBLE,
    SYNTHESIS
}

sealed interface ColdRunUiState {
    data object Idle : ColdRunUiState
    data class Running(val progress: ProbeExecutionProgress) : ColdRunUiState
    data class Completed(val sessionId: String) : ColdRunUiState
    data class Error(val message: String) : ColdRunUiState
}

sealed interface AiUiState {
    data object Idle : AiUiState
    data object Loading : AiUiState
    data class Error(val message: String) : AiUiState
    data object Ready : AiUiState
}

class DiagnosticViewModel(
    private val runColdDiagnosticUseCase: RunColdDiagnosticUseCase,
    private val finalizeLiveTraceUseCase: FinalizeLiveTraceUseCase,
    private val repository: DiagnosticRepository,
    private val liveTraceCoordinator: LiveTraceCoordinator,
    private val biometricInspector: AndroidBiometricInspector,
    private val privilegeManager: PrivilegeManager,
    private val aiAdvisorService: AiAdvisorService,
    private val appContext: android.content.Context
) : ViewModel() {

    private val _coldState = MutableStateFlow<ColdRunUiState>(ColdRunUiState.Idle)
    val coldState: StateFlow<ColdRunUiState> = _coldState.asStateFlow()

    private val _selectedSection = MutableStateFlow(DashboardSection.OVERVIEW)
    val selectedSection: StateFlow<DashboardSection> = _selectedSection.asStateFlow()

    private val _aiState = MutableStateFlow<AiUiState>(AiUiState.Idle)
    val aiState: StateFlow<AiUiState> = _aiState.asStateFlow()

    private val _showAiConsentDialog = MutableStateFlow(false)
    val showAiConsentDialog: StateFlow<Boolean> = _showAiConsentDialog.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    val activeSession: StateFlow<DiagnosticSession?> = repository.activeSession
    val liveProgress: StateFlow<LiveTraceProgress> = liveTraceCoordinator.progress
    val isFirebaseAiAvailable: Boolean get() = aiAdvisorService.isFirebaseConfigured()

    init {
        viewModelScope.launch {
            val existing = repository.sessions.firstOrNull()?.firstOrNull()
            if (existing != null && repository.activeSession.value == null) {
                repository.setActiveSession(existing.sessionId)
            }
        }
    }

    fun selectSection(section: DashboardSection) {
        _selectedSection.value = section
    }

    fun clearStatusMessage() {
        _statusMessage.value = null
    }

    fun startColdAnalysis() {
        if (_coldState.value is ColdRunUiState.Running) return
        viewModelScope.launch {
            _coldState.value = ColdRunUiState.Running(
                ProbeExecutionProgress(0, ProbeDomain.entries.size, ProbeDomain.HARDWARE)
            )
            try {
                runColdDiagnosticUseCase().collect { (progress, session) ->
                    if (session == null) {
                        _coldState.value = ColdRunUiState.Running(progress)
                    } else {
                        _coldState.value = ColdRunUiState.Completed(session.sessionId)
                        _selectedSection.value = DashboardSection.OVERVIEW
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _coldState.value = ColdRunUiState.Error(e.localizedMessage ?: "Cold diagnostic failed.")
            }
        }
    }

    fun startLiveTracerAndBuildEnrollmentIntent(): Intent? {
        val currentSession = activeSession.value
        FodLiveTracerService.start(appContext)
        liveTraceCoordinator.startSession(currentSession)

        val candidates = biometricInspector.resolveEnrollmentIntents()
        val chosen = candidates.firstOrNull()
        if (chosen != null) {
            liveTraceCoordinator.markEnrollmentIntentOpened(chosen.action ?: "BIOMETRIC_ENROLL")
        } else {
            _statusMessage.value = "No system biometric enrollment activity resolved on this ROM."
        }
        return chosen
    }

    fun stopLiveTracerAndCorrelate() {
        viewModelScope.launch {
            try {
                val (liveData, liveEvidence) = liveTraceCoordinator.finishAndCollect()
                FodLiveTracerService.stop(appContext)
                val base = activeSession.value ?: return@launch
                finalizeLiveTraceUseCase(base, liveData, liveEvidence)
                _selectedSection.value = DashboardSection.TIMELINE
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _statusMessage.value = e.localizedMessage ?: "Failed to finalize live trace."
            }
        }
    }

    fun requestAiAnalysisConsent() {
        _showAiConsentDialog.value = true
    }

    fun dismissAiConsent() {
        _showAiConsentDialog.value = false
    }

    fun confirmAndRunAiAnalysis() {
        _showAiConsentDialog.value = false
        val session = activeSession.value ?: return
        viewModelScope.launch {
            _aiState.value = AiUiState.Loading
            val res = aiAdvisorService.analyzeDiagnostic(session)
            res.onSuccess { analysis ->
                val updated = session.copy(
                    updatedAtCivilMs = System.currentTimeMillis(),
                    aiAnalysis = analysis
                )
                repository.saveSession(updated)
                _aiState.value = AiUiState.Ready
                _selectedSection.value = DashboardSection.SYNTHESIS
            }.onFailure { err ->
                _aiState.value = AiUiState.Error(err.localizedMessage ?: "AI analysis failed.")
            }
        }
    }

    class Factory(private val container: com.example.fodtracer.presentation.AppContainer) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return DiagnosticViewModel(
                runColdDiagnosticUseCase = container.runColdDiagnosticUseCase,
                finalizeLiveTraceUseCase = container.finalizeLiveTraceUseCase,
                repository = container.diagnosticRepository,
                liveTraceCoordinator = container.liveTraceCoordinator,
                biometricInspector = container.biometricInspector,
                privilegeManager = container.privilegeManager,
                aiAdvisorService = container.aiAdvisorService,
                appContext = container.appContext
            ) as T
        }
    }
}
