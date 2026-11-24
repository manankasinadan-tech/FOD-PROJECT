package com.example.fodtracer.presentation.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.models.LanguagePreference
import com.example.fodtracer.domain.models.ThemePreference
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class SettingsViewModel(
    private val privilegeManager: PrivilegeManager,
    private val preferencesRepository: PreferencesRepository,
    private val shellExecutor: ShellExecutor,
    private val aiAdvisorService: AiAdvisorService
) : ViewModel() {

    val privilegeSnapshot: StateFlow<PrivilegeSnapshot> = privilegeManager.snapshot
    val shellLogs: StateFlow<List<ShellLogEntry>> = shellExecutor.recentLogs

    val themePreference: StateFlow<ThemePreference> = preferencesRepository.themePreference
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), ThemePreference.LIGHT)

    val languagePreference: StateFlow<LanguagePreference> = preferencesRepository.languagePreference
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), LanguagePreference.SYSTEM)

    val aiEnabled: StateFlow<Boolean> = preferencesRepository.aiEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)

    val anonymizeByDefault: StateFlow<Boolean> = preferencesRepository.anonymizeByDefault
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)

    val isFirebaseAiConfigured: Boolean get() = aiAdvisorService.isFirebaseConfigured()

    init {
        refreshPrivileges()
    }

    fun refreshPrivileges() {
        viewModelScope.launch {
            privilegeManager.refreshStatus()
        }
    }

    fun requestAndTestRoot() {
        viewModelScope.launch {
            privilegeManager.requestAndVerifyRoot()
        }
    }

    fun setTheme(pref: ThemePreference) {
        viewModelScope.launch { preferencesRepository.setThemePreference(pref) }
    }

    fun setLanguage(pref: LanguagePreference) {
        viewModelScope.launch { preferencesRepository.setLanguagePreference(pref) }
    }

    fun setAiEnabled(enabled: Boolean) {
        viewModelScope.launch { preferencesRepository.setAiEnabled(enabled) }
    }

    fun setAnonymizeByDefault(enabled: Boolean) {
        viewModelScope.launch { preferencesRepository.setAnonymizeByDefault(enabled) }
    }

    class Factory(private val container: com.example.fodtracer.presentation.AppContainer) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return SettingsViewModel(
                privilegeManager = container.privilegeManager,
                preferencesRepository = container.preferencesRepository,
                shellExecutor = container.shellExecutor,
                aiAdvisorService = container.aiAdvisorService
            ) as T
        }
    }
}
