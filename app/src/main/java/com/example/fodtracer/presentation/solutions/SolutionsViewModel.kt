package com.example.fodtracer.presentation.solutions

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.fodtracer.domain.interfaces.AiAdvisorService
import com.example.fodtracer.domain.interfaces.DiagnosticRepository
import com.example.fodtracer.domain.models.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

class SolutionsViewModel(
    private val repository: DiagnosticRepository,
    private val aiAdvisorService: AiAdvisorService
) : ViewModel() {

    private val _selectedCategory = MutableStateFlow<SolutionCategory?>(null)
    val selectedCategory: StateFlow<SolutionCategory?> = _selectedCategory.asStateFlow()

    private val _isAiRunning = MutableStateFlow(false)
    val isAiRunning: StateFlow<Boolean> = _isAiRunning.asStateFlow()

    private val _aiError = MutableStateFlow<String?>(null)
    val aiError: StateFlow<String?> = _aiError.asStateFlow()

    val activeSession: StateFlow<DiagnosticSession?> = repository.activeSession
    val latestComparison: StateFlow<ComparisonReport?> = repository.comparisons
        .map { it.firstOrNull() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    val allProposals: StateFlow<List<SolutionProposal>> = combine(activeSession, latestComparison) { sess, cmp ->
        val fromSess = sess?.solutions.orEmpty()
        val fromCmp = cmp?.candidateSolutions.orEmpty()
        (fromCmp + fromSess).distinctBy { it.id }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val isFirebaseAiAvailable: Boolean get() = aiAdvisorService.isFirebaseConfigured()

    fun filterByCategory(category: SolutionCategory?) {
        _selectedCategory.value = category
    }

    fun clearAiError() {
        _aiError.value = null
    }

    fun triggerAiSynthesis() {
        val sess = activeSession.value
        val cmp = latestComparison.value
        viewModelScope.launch {
            _isAiRunning.value = true
            _aiError.value = null
            when {
                sess != null -> {
                    aiAdvisorService.analyzeDiagnostic(sess)
                        .onSuccess { ai ->
                            repository.saveSession(sess.copy(aiAnalysis = ai, updatedAtCivilMs = System.currentTimeMillis()))
                        }
                        .onFailure { _aiError.value = it.localizedMessage ?: "AI analysis failed." }
                }
                cmp != null -> {
                    aiAdvisorService.analyzeComparison(cmp)
                        .onSuccess { ai ->
                            repository.saveComparison(cmp.copy(aiAnalysis = ai))
                        }
                        .onFailure { _aiError.value = it.localizedMessage ?: "AI analysis failed." }
                }
                else -> {
                    _aiError.value = "Run a diagnostic or comparison first."
                }
            }
            _isAiRunning.value = false
        }
    }

    class Factory(private val container: com.example.fodtracer.presentation.AppContainer) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return SolutionsViewModel(
                repository = container.diagnosticRepository,
                aiAdvisorService = container.aiAdvisorService
            ) as T
        }
    }
}
