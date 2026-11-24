package com.example.fodtracer.presentation.comparator

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.fodtracer.core.comparator.ReferenceBaselineFixtures
import com.example.fodtracer.domain.interfaces.AiAdvisorService
import com.example.fodtracer.domain.interfaces.ArchiveRepository
import com.example.fodtracer.domain.interfaces.DiagnosticRepository
import com.example.fodtracer.domain.models.ComparisonReport
import com.example.fodtracer.domain.models.DiagnosticSession
import com.example.fodtracer.domain.usecases.CompareArchivesUseCase
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

class ComparatorViewModel(
    private val archiveRepository: ArchiveRepository,
    private val diagnosticRepository: DiagnosticRepository,
    private val compareArchivesUseCase: CompareArchivesUseCase,
    private val aiAdvisorService: AiAdvisorService
) : ViewModel() {

    private val _archiveA = MutableStateFlow<DiagnosticSession?>(null)
    val archiveA: StateFlow<DiagnosticSession?> = _archiveA.asStateFlow()

    private val _archiveB = MutableStateFlow<DiagnosticSession?>(null)
    val archiveB: StateFlow<DiagnosticSession?> = _archiveB.asStateFlow()

    private val _report = MutableStateFlow<ComparisonReport?>(null)
    val report: StateFlow<ComparisonReport?> = _report.asStateFlow()

    private val _isComparing = MutableStateFlow(false)
    val isComparing: StateFlow<Boolean> = _isComparing.asStateFlow()

    private val _isAiRunning = MutableStateFlow(false)
    val isAiRunning: StateFlow<Boolean> = _isAiRunning.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    val savedSessions: StateFlow<List<DiagnosticSession>> = diagnosticRepository.sessions
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val isFirebaseAiAvailable: Boolean get() = aiAdvisorService.isFirebaseConfigured()

    fun clearError() {
        _errorMessage.value = null
    }

    fun importArchiveA(uri: Uri) {
        viewModelScope.launch {
            archiveRepository.importDiagnosticZip(uri)
                .onSuccess { _archiveA.value = it }
                .onFailure { _errorMessage.value = it.localizedMessage ?: "Invalid ZIP Archive A" }
        }
    }

    fun importArchiveB(uri: Uri) {
        viewModelScope.launch {
            archiveRepository.importDiagnosticZip(uri)
                .onSuccess { _archiveB.value = it }
                .onFailure { _errorMessage.value = it.localizedMessage ?: "Invalid ZIP Archive B" }
        }
    }

    fun selectLocalSessionAsA(session: DiagnosticSession) {
        _archiveA.value = session
    }

    fun selectLocalSessionAsB(session: DiagnosticSession) {
        _archiveB.value = session
    }

    fun loadReferenceDemoPair() {
        _archiveA.value = ReferenceBaselineFixtures.createWorkingCustomRomBaseline()
        _archiveB.value = ReferenceBaselineFixtures.createFailingGsiBaseline()
        runComparison()
    }

    fun runComparison() {
        val a = _archiveA.value ?: return
        val b = _archiveB.value ?: return
        viewModelScope.launch {
            _isComparing.value = true
            try {
                _report.value = compareArchivesUseCase(a, b)
            } catch (e: Exception) {
                _errorMessage.value = e.localizedMessage ?: "Comparison failed."
            } finally {
                _isComparing.value = false
            }
        }
    }

    fun runAiOnComparison() {
        val current = _report.value ?: return
        viewModelScope.launch {
            _isAiRunning.value = true
            aiAdvisorService.analyzeComparison(current)
                .onSuccess { ai ->
                    val updated = current.copy(aiAnalysis = ai)
                    _report.value = updated
                    diagnosticRepository.saveComparison(updated)
                }
                .onFailure { err ->
                    _errorMessage.value = err.localizedMessage ?: "AI comparison analysis failed."
                }
            _isAiRunning.value = false
        }
    }

    class Factory(private val container: com.example.fodtracer.presentation.AppContainer) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return ComparatorViewModel(
                archiveRepository = container.archiveRepository,
                diagnosticRepository = container.diagnosticRepository,
                compareArchivesUseCase = container.compareArchivesUseCase,
                aiAdvisorService = container.aiAdvisorService
            ) as T
        }
    }
}
