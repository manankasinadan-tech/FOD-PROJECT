package com.example.fodtracer.data.repositories

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.fodtracer.data.archives.ArchiveManager
import com.example.fodtracer.data.database.ComparisonEntity
import com.example.fodtracer.data.database.FodDao
import com.example.fodtracer.data.database.SessionEntity
import com.example.fodtracer.data.serialization.FodJson
import com.example.fodtracer.domain.interfaces.DiagnosticRepository
import com.example.fodtracer.domain.interfaces.PreferencesRepository
import com.example.fodtracer.domain.models.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

private val Context.fodDataStore: DataStore<Preferences> by preferencesDataStore(name = "fodtracer_prefs")

class RoomDiagnosticRepository(
    private val dao: FodDao,
    private val archiveManager: ArchiveManager
) : DiagnosticRepository {

    private val _activeSession = MutableStateFlow<DiagnosticSession?>(null)
    override val activeSession: StateFlow<DiagnosticSession?> = _activeSession.asStateFlow()

    override val sessions: Flow<List<DiagnosticSession>> = dao.observeSessions()
        .map { rows ->
            rows.mapNotNull { row ->
                runCatching { FodJson.compactCodec.decodeFromString<DiagnosticSession>(row.payloadJson) }.getOrNull()
            }
        }
        .catch { emit(emptyList()) }

    override val comparisons: Flow<List<ComparisonReport>> = dao.observeComparisons()
        .map { rows ->
            rows.mapNotNull { row ->
                runCatching { FodJson.compactCodec.decodeFromString<ComparisonReport>(row.payloadJson) }.getOrNull()
            }
        }
        .catch { emit(emptyList()) }

    override suspend fun saveSession(session: DiagnosticSession) {
        archiveManager.persistStructuredSessionDir(session)
        val dbJson = encodeDbSafeSessionJson(session)
        dao.upsertSession(
            SessionEntity(
                sessionId = session.sessionId,
                label = session.label,
                createdAtCivilMs = session.createdAtCivilMs,
                updatedAtCivilMs = session.updatedAtCivilMs,
                deviceModel = "${session.environment.manufacturer} ${session.environment.model}",
                romType = session.environment.detectedRomType.name,
                hasLiveTrace = session.liveTrace != null,
                anomalyCount = session.anomalies.size,
                payloadJson = dbJson
            )
        )
        _activeSession.value = session
    }

    override suspend fun getSessionById(sessionId: String): DiagnosticSession? {
        archiveManager.loadFullSessionFromDisk(sessionId)?.let { return it }
        val entity = runCatching { dao.getSession(sessionId) }.getOrNull() ?: return null
        return runCatching { FodJson.compactCodec.decodeFromString<DiagnosticSession>(entity.payloadJson) }.getOrNull()
    }

    override suspend fun deleteSession(sessionId: String) {
        runCatching { dao.deleteSession(sessionId) }
        archiveManager.deleteStructuredSessionDir(sessionId)
        if (_activeSession.value?.sessionId == sessionId) {
            _activeSession.value = null
        }
    }

    override suspend fun setActiveSession(sessionId: String?) {
        _activeSession.value = sessionId?.let { getSessionById(it) }
    }

    override suspend fun saveComparison(report: ComparisonReport) {
        val json = FodJson.compactCodec.encodeToString(report)
        if (json.length <= MAX_DB_PAYLOAD_BYTES) {
            dao.upsertComparison(
                ComparisonEntity(
                    comparisonId = report.comparisonId,
                    createdAtCivilMs = report.createdAtCivilMs,
                    archiveALabel = report.archiveALabel,
                    archiveBLabel = report.archiveBLabel,
                    payloadJson = json
                )
            )
        }
        archiveManager.persistComparisonReport(report)
    }

    override suspend fun getComparisonById(comparisonId: String): ComparisonReport? {
        val entity = runCatching { dao.getComparison(comparisonId) }.getOrNull() ?: return null
        return runCatching { FodJson.compactCodec.decodeFromString<ComparisonReport>(entity.payloadJson) }.getOrNull()
    }

    private fun encodeDbSafeSessionJson(session: DiagnosticSession): String {
        // Never inline rawArtifacts into SQLite (stored on disk in diagnostics/<id>/ & session_full.json)
        val noRaw = session.copy(rawArtifacts = emptyMap())
        val firstPass = FodJson.compactCodec.encodeToString(noRaw)
        if (firstPass.length <= MAX_DB_PAYLOAD_BYTES) return firstPass

        // Second pass: trim disassembly snippets & long trace buffers in the SQLite summary row
        val trimmedDisasm = noRaw.disassembledArtifacts.map { art ->
            art.copy(
                keySymbols = art.keySymbols.take(25),
                extractedStrings = art.extractedStrings.take(25),
                crossReferences = art.crossReferences.take(25),
                decodedResources = art.decodedResources.take(30),
                disassemblySnippet = art.disassemblySnippet.lines().take(12).joinToString("\n")
            )
        }
        val trimmedLive = noRaw.liveTrace?.copy(
            events = noRaw.liveTrace.events.take(250),
            binderTransactions = noRaw.liveTrace.binderTransactions.take(40),
            tracefsEvents = noRaw.liveTrace.tracefsEvents.take(40),
            dumpsysDiffs = noRaw.liveTrace.dumpsysDiffs.take(15),
            surfaceFlingerSnapshot = noRaw.liveTrace.surfaceFlingerSnapshot?.take(8_000),
            dumpsysFingerprintDelta = noRaw.liveTrace.dumpsysFingerprintDelta?.take(8_000),
            runtimeSnapshots = noRaw.liveTrace.runtimeSnapshots.take(15)
        )
        val secondPass = FodJson.compactCodec.encodeToString(
            noRaw.copy(
                disassembledArtifacts = trimmedDisasm,
                liveTrace = trimmedLive
            )
        )
        if (secondPass.length <= MAX_DB_PAYLOAD_BYTES) return secondPass

        // Final fallback: keep core environment, probes, mechanism steps & solutions strictly under CursorWindow limit
        return FodJson.compactCodec.encodeToString(
            noRaw.copy(
                disassembledArtifacts = emptyList(),
                evidence = noRaw.evidence.take(120),
                liveTrace = trimmedLive?.copy(
                    events = trimmedLive.events.take(80),
                    binderTransactions = emptyList(),
                    tracefsEvents = emptyList(),
                    dumpsysDiffs = emptyList(),
                    surfaceFlingerSnapshot = null,
                    dumpsysFingerprintDelta = null,
                    runtimeSnapshots = trimmedLive.runtimeSnapshots.take(8),
                    rawBufferTruncated = true
                )
            )
        )
    }

    companion object {
        private const val MAX_DB_PAYLOAD_BYTES = 850_000
    }
}

class DataStorePreferencesRepository(
    private val context: Context
) : PreferencesRepository {

    private object Keys {
        val THEME = stringPreferencesKey("theme_preference")
        val LANGUAGE = stringPreferencesKey("language_preference")
        val AI_ENABLED = booleanPreferencesKey("ai_enabled")
        val ANONYMIZE_DEFAULT = booleanPreferencesKey("anonymize_default")
        val PREFER_ROOT_PROBES = booleanPreferencesKey("prefer_root_probes")
    }

    override val themePreference: Flow<ThemePreference> = context.fodDataStore.data.map { prefs ->
        val raw = prefs[Keys.THEME] ?: ThemePreference.LIGHT.name
        runCatching { ThemePreference.valueOf(raw) }.getOrDefault(ThemePreference.LIGHT)
    }

    override val languagePreference: Flow<LanguagePreference> = context.fodDataStore.data.map { prefs ->
        val raw = prefs[Keys.LANGUAGE] ?: LanguagePreference.SYSTEM.name
        runCatching { LanguagePreference.valueOf(raw) }.getOrDefault(LanguagePreference.SYSTEM)
    }

    override val aiEnabled: Flow<Boolean> = context.fodDataStore.data.map { prefs ->
        prefs[Keys.AI_ENABLED] ?: true
    }

    override val anonymizeByDefault: Flow<Boolean> = context.fodDataStore.data.map { prefs ->
        prefs[Keys.ANONYMIZE_DEFAULT] ?: true
    }

    override val preferRootProbes: Flow<Boolean> = context.fodDataStore.data.map { prefs ->
        prefs[Keys.PREFER_ROOT_PROBES] ?: true
    }

    override suspend fun setThemePreference(pref: ThemePreference) {
        context.fodDataStore.edit { it[Keys.THEME] = pref.name }
    }

    override suspend fun setLanguagePreference(pref: LanguagePreference) {
        context.fodDataStore.edit { it[Keys.LANGUAGE] = pref.name }
    }

    override suspend fun setAiEnabled(enabled: Boolean) {
        context.fodDataStore.edit { it[Keys.AI_ENABLED] = enabled }
    }

    override suspend fun setAnonymizeByDefault(enabled: Boolean) {
        context.fodDataStore.edit { it[Keys.ANONYMIZE_DEFAULT] = enabled }
    }

    override suspend fun setPreferRootProbes(enabled: Boolean) {
        context.fodDataStore.edit { it[Keys.PREFER_ROOT_PROBES] = enabled }
    }
}
