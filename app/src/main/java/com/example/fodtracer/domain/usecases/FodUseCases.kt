package com.example.fodtracer.domain.usecases

import com.example.fodtracer.core.anomaly.AnomalyEngine
import com.example.fodtracer.core.comparator.ComparatorEngine
import com.example.fodtracer.core.correlation.CorrelationEngine
import com.example.fodtracer.core.disasm.DeepArtifactEngine
import com.example.fodtracer.core.disasm.FodLogicReconstructor
import com.example.fodtracer.core.evidence.EvidenceEngine
import com.example.fodtracer.core.probe.ColdDiscoveryOutput
import com.example.fodtracer.core.probe.ProbeEngine
import com.example.fodtracer.core.probe.ProbeExecutionProgress
import com.example.fodtracer.core.solution.SolutionEngine
import com.example.fodtracer.domain.interfaces.DiagnosticRepository
import com.example.fodtracer.domain.models.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class RunColdDiagnosticUseCase(
    private val probeEngine: ProbeEngine,
    private val evidenceEngine: EvidenceEngine,
    private val correlationEngine: CorrelationEngine,
    private val anomalyEngine: AnomalyEngine,
    private val solutionEngine: SolutionEngine,
    private val deepArtifactEngine: DeepArtifactEngine,
    private val repository: DiagnosticRepository
) {
    operator fun invoke(): Flow<Pair<ProbeExecutionProgress, DiagnosticSession?>> {
        return probeEngine.runColdDiagnostic().map { (progress, discovery) ->
            if (discovery == null) {
                progress to null
            } else {
                val session = assembleSession(discovery)
                repository.saveSession(session)
                progress to session
            }
        }.flowOn(Dispatchers.IO)
    }

    private suspend fun assembleSession(discovery: ColdDiscoveryOutput): DiagnosticSession {
        val now = System.currentTimeMillis()
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date(now))
        val sessionId = "FOD-$stamp-${discovery.environment.device.take(10)}"

        val rawEvidence = evidenceEngine.buildColdEvidence(discovery.probeResults)
        val linkedComponents = evidenceEngine.attachComponentEvidenceLinks(discovery.components, rawEvidence)
        val correlationOut = correlationEngine.correlate(linkedComponents, rawEvidence, liveTrace = null)
        val anomalyOut = anomalyEngine.analyze(
            environment = discovery.environment,
            probeResults = discovery.probeResults,
            components = linkedComponents,
            evidence = rawEvidence,
            liveTrace = null
        )

        val allowRoot = discovery.environment.rootState == RootState.GRANTED_VERIFIED
        val deepOut = deepArtifactEngine.inspectAll(
            probeResults = discovery.probeResults,
            runtimeSnapshots = emptyList(),
            allowRoot = allowRoot
        )
        val mechanismSteps = FodLogicReconstructor.reconstruct(
            probeResults = discovery.probeResults,
            artifacts = deepOut.artifacts,
            liveTrace = null
        )

        val preliminary = DiagnosticSession(
            sessionId = sessionId,
            label = "${discovery.environment.manufacturer} ${discovery.environment.model} (${discovery.environment.detectedRomType.name})",
            createdAtCivilMs = now,
            updatedAtCivilMs = now,
            environment = discovery.environment,
            probeResults = discovery.probeResults,
            components = linkedComponents,
            dependencies = correlationOut.dependencyLinks,
            evidence = rawEvidence,
            liveTrace = null,
            correlations = correlationOut.correlations,
            anomalies = anomalyOut.anomalies,
            hypotheses = anomalyOut.hypotheses,
            solutions = emptyList(),
            rawArtifacts = deepOut.rawFiles,
            disassembledArtifacts = deepOut.artifacts,
            mechanismSteps = mechanismSteps
        )
        val solutions = solutionEngine.evaluateDiagnostic(preliminary)
        return preliminary.copy(solutions = solutions)
    }
}

class FinalizeLiveTraceUseCase(
    private val correlationEngine: CorrelationEngine,
    private val anomalyEngine: AnomalyEngine,
    private val solutionEngine: SolutionEngine,
    private val deepArtifactEngine: DeepArtifactEngine,
    private val repository: DiagnosticRepository
) {
    suspend operator fun invoke(
        baseSession: DiagnosticSession,
        liveTrace: LiveTraceData,
        liveEvidence: List<EvidenceRecord>
    ): DiagnosticSession {
        val mergedEvidence = (baseSession.evidence + liveEvidence).distinctBy { it.id }

        val allowRoot = baseSession.environment.rootState == RootState.GRANTED_VERIFIED
        val deepOut = deepArtifactEngine.inspectAll(
            probeResults = baseSession.probeResults,
            runtimeSnapshots = liveTrace.runtimeSnapshots,
            allowRoot = allowRoot
        )
        val mergedArtifacts = (baseSession.disassembledArtifacts + deepOut.artifacts)
            .associateBy { "${it.path}|${it.kind.name}" }
            .values
            .toList()
        val mergedRaw = baseSession.rawArtifacts.toMutableMap().apply {
            putAll(deepOut.rawFiles)
        }

        // Correlate every live runtime event directly to exact disassembled symbols, call chains & /proc/<pid> states
        val enrichedEvents = com.example.fodtracer.core.disasm.CodeRuntimeCorrelator.correlateTimelineEvents(
            events = liveTrace.events,
            artifacts = mergedArtifacts,
            runtimeSnapshots = liveTrace.runtimeSnapshots
        )
        val enrichedLiveTrace = liveTrace.copy(events = enrichedEvents)

        val correlationOut = correlationEngine.correlate(
            components = baseSession.components,
            evidence = mergedEvidence,
            liveTrace = enrichedLiveTrace
        )
        val anomalyOut = anomalyEngine.analyze(
            environment = baseSession.environment,
            probeResults = baseSession.probeResults,
            components = baseSession.components,
            evidence = mergedEvidence,
            liveTrace = enrichedLiveTrace
        )
        val mechanismSteps = FodLogicReconstructor.reconstruct(
            probeResults = baseSession.probeResults,
            artifacts = mergedArtifacts,
            liveTrace = enrichedLiveTrace
        )

        val updated = baseSession.copy(
            updatedAtCivilMs = System.currentTimeMillis(),
            evidence = mergedEvidence,
            liveTrace = enrichedLiveTrace,
            dependencies = correlationOut.dependencyLinks,
            correlations = correlationOut.correlations,
            anomalies = anomalyOut.anomalies,
            hypotheses = anomalyOut.hypotheses,
            rawArtifacts = mergedRaw,
            disassembledArtifacts = mergedArtifacts,
            mechanismSteps = mechanismSteps
        )
        val solutions = solutionEngine.evaluateDiagnostic(updated)
        val finalSession = updated.copy(solutions = solutions)
        repository.saveSession(finalSession)
        return finalSession
    }
}

class CompareArchivesUseCase(
    private val comparatorEngine: ComparatorEngine,
    private val solutionEngine: SolutionEngine,
    private val repository: DiagnosticRepository
) {
    suspend operator fun invoke(
        romA: DiagnosticSession,
        gsiB: DiagnosticSession
    ): ComparisonReport {
        val rawReport = comparatorEngine.compare(romA, gsiB)
        val solutions = solutionEngine.evaluateComparison(rawReport, romA, gsiB)
        val finalReport = rawReport.copy(candidateSolutions = solutions)
        repository.saveComparison(finalReport)
        return finalReport
    }
}
