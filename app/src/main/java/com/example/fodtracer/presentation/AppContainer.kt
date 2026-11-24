package com.example.fodtracer.presentation

import android.content.Context
import com.example.fodtracer.core.ai.FirebaseAiAdvisorService
import com.example.fodtracer.core.anomaly.AnomalyEngine
import com.example.fodtracer.core.comparator.ComparatorEngine
import com.example.fodtracer.core.correlation.CorrelationEngine
import com.example.fodtracer.core.disasm.DeepArtifactEngine
import com.example.fodtracer.core.evidence.EvidenceEngine
import com.example.fodtracer.core.probe.ProbeEngine
import com.example.fodtracer.core.solution.SolutionEngine
import com.example.fodtracer.data.archives.ArchiveManager
import com.example.fodtracer.data.database.FodDatabase
import com.example.fodtracer.data.repositories.DataStorePreferencesRepository
import com.example.fodtracer.data.repositories.RoomDiagnosticRepository
import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.usecases.CompareArchivesUseCase
import com.example.fodtracer.domain.usecases.FinalizeLiveTraceUseCase
import com.example.fodtracer.domain.usecases.RunColdDiagnosticUseCase
import com.example.fodtracer.system.biometrics.AndroidBiometricInspector
import com.example.fodtracer.system.root.AndroidPrivilegeManager
import com.example.fodtracer.system.selinux.SeLinuxInspector
import com.example.fodtracer.system.shell.SafeShellExecutor
import com.example.fodtracer.workers.live.LiveTraceCoordinator

class AppContainer(context: Context) {
    val appContext: Context = context.applicationContext

    val shellExecutor: ShellExecutor = SafeShellExecutor()
    val seLinuxInspector = SeLinuxInspector(shellExecutor)
    val privilegeManager: PrivilegeManager = AndroidPrivilegeManager(appContext, shellExecutor, seLinuxInspector)
    val biometricInspector = AndroidBiometricInspector(appContext)

    val archiveManager = ArchiveManager(appContext)
    val archiveRepository: ArchiveRepository = archiveManager
    val database = FodDatabase.getInstance(appContext)
    val diagnosticRepository: DiagnosticRepository = RoomDiagnosticRepository(database.fodDao(), archiveManager)
    val preferencesRepository: PreferencesRepository = DataStorePreferencesRepository(appContext)
    val aiAdvisorService: AiAdvisorService = FirebaseAiAdvisorService(appContext)

    val probeEngine = ProbeEngine(appContext, shellExecutor, privilegeManager)
    val deepArtifactEngine = DeepArtifactEngine(shellExecutor)
    val evidenceEngine = EvidenceEngine()
    val correlationEngine = CorrelationEngine()
    val anomalyEngine = AnomalyEngine()
    val solutionEngine = SolutionEngine()
    val comparatorEngine = ComparatorEngine()

    val liveTraceCoordinator = LiveTraceCoordinator(appContext, shellExecutor, privilegeManager)

    val runColdDiagnosticUseCase = RunColdDiagnosticUseCase(
        probeEngine = probeEngine,
        evidenceEngine = evidenceEngine,
        correlationEngine = correlationEngine,
        anomalyEngine = anomalyEngine,
        solutionEngine = solutionEngine,
        deepArtifactEngine = deepArtifactEngine,
        repository = diagnosticRepository
    )

    val finalizeLiveTraceUseCase = FinalizeLiveTraceUseCase(
        correlationEngine = correlationEngine,
        anomalyEngine = anomalyEngine,
        solutionEngine = solutionEngine,
        deepArtifactEngine = deepArtifactEngine,
        repository = diagnosticRepository
    )

    val compareArchivesUseCase = CompareArchivesUseCase(
        comparatorEngine = comparatorEngine,
        solutionEngine = solutionEngine,
        repository = diagnosticRepository
    )
}
