package com.example.fodtracer.presentation.archives

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.fodtracer.domain.interfaces.ArchiveRepository
import com.example.fodtracer.domain.interfaces.DiagnosticRepository
import com.example.fodtracer.domain.interfaces.PreferencesRepository
import com.example.fodtracer.domain.models.DiagnosticSession
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

class ArchivesViewModel(
    private val diagnosticRepository: DiagnosticRepository,
    private val archiveRepository: ArchiveRepository,
    private val preferencesRepository: PreferencesRepository
) : ViewModel() {

    val sessions: StateFlow<List<DiagnosticSession>> = diagnosticRepository.sessions
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val anonymizeByDefault: StateFlow<Boolean> = preferencesRepository.anonymizeByDefault
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)

    private val _publicExports = MutableStateFlow<List<String>>(emptyList())
    val publicExports: StateFlow<List<String>> = _publicExports.asStateFlow()

    private val _feedbackMessage = MutableStateFlow<String?>(null)
    val feedbackMessage: StateFlow<String?> = _feedbackMessage.asStateFlow()

    init {
        refreshPublicArchives()
    }

    fun refreshPublicArchives() {
        viewModelScope.launch {
            _publicExports.value = archiveRepository.listPublicArchives()
        }
    }

    fun clearFeedback() {
        _feedbackMessage.value = null
    }

    fun exportSession(session: DiagnosticSession, anonymize: Boolean, destinationUri: Uri? = null) {
        viewModelScope.launch {
            archiveRepository.exportDiagnosticZip(session, anonymize, destinationUri)
                .onSuccess { path ->
                    _feedbackMessage.value = "Exported ZIP: $path"
                    refreshPublicArchives()
                }
                .onFailure { err ->
                    _feedbackMessage.value = "Export failed: ${err.localizedMessage}"
                }
        }
    }

    fun exportSessionMarkdown(session: DiagnosticSession, anonymize: Boolean, destinationUri: Uri? = null) {
        viewModelScope.launch {
            archiveRepository.exportDiagnosticMarkdown(session, anonymize, destinationUri)
                .onSuccess { path ->
                    _feedbackMessage.value = "Exported MD: $path"
                    refreshPublicArchives()
                }
                .onFailure { err ->
                    _feedbackMessage.value = "MD export failed: ${err.localizedMessage}"
                }
        }
    }

    fun importZipFromUri(uri: Uri, onImported: () -> Unit) {
        viewModelScope.launch {
            archiveRepository.importDiagnosticZip(uri)
                .onSuccess { imported ->
                    diagnosticRepository.saveSession(imported)
                    diagnosticRepository.setActiveSession(imported.sessionId)
                    _feedbackMessage.value = "Imported & verified: ${imported.sessionId}"
                    onImported()
                }
                .onFailure { err ->
                    _feedbackMessage.value = "Import rejected: ${err.localizedMessage}"
                }
        }
    }

    fun openSession(sessionId: String, onReady: () -> Unit) {
        viewModelScope.launch {
            diagnosticRepository.setActiveSession(sessionId)
            onReady()
        }
    }

    fun deleteSession(sessionId: String) {
        viewModelScope.launch {
            diagnosticRepository.deleteSession(sessionId)
        }
    }

    class Factory(private val container: com.example.fodtracer.presentation.AppContainer) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return ArchivesViewModel(
                diagnosticRepository = container.diagnosticRepository,
                archiveRepository = container.archiveRepository,
                preferencesRepository = container.preferencesRepository
            ) as T
        }
    }
}
