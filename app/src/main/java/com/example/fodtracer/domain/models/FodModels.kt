package com.example.fodtracer.domain.models

import kotlinx.serialization.Serializable

const val FODTRACER_SCHEMA_VERSION = 1

@Serializable
enum class EpistemicLevel {
    PROVED,
    CORRELATED,
    HYPOTHESIS,
    INACCESSIBLE
}

@Serializable
enum class DiscoveryStatus {
    FOUND,
    NOT_FOUND,
    INACCESSIBLE,
    UNSUPPORTED,
    ERROR,
    PARTIAL
}

@Serializable
enum class AccessLevel {
    ANDROID_API,
    UNPRIVILEGED_FS,
    UNPRIVILEGED_SHELL,
    ROOT_SU
}

@Serializable
enum class ProbeDomain {
    HARDWARE,
    BIOMETRIC,
    FRAMEWORK,
    SYSTEMUI,
    HAL,
    VENDOR,
    DISPLAY,
    KERNEL,
    TOUCH,
    OVERLAY,
    SELINUX,
    PROPERTIES
}

@Serializable
enum class ComponentRole {
    APPLICATION_SYSTEMUI,
    FRAMEWORK_BIOMETRIC,
    BIOMETRIC_SERVICE,
    UDFPS_CONTROLLER,
    BIOMETRIC_HAL,
    VENDOR_SERVICE,
    KERNEL_DRIVER,
    DISPLAY_HBM,
    TOUCH_CONTROLLER,
    RESOURCE_OVERLAY,
    SELINUX_POLICY,
    SYSTEM_PROPERTY
}

@Serializable
enum class PartitionOrigin {
    SYSTEM,
    SYSTEM_EXT,
    PRODUCT,
    VENDOR,
    ODM,
    KERNEL,
    APEX,
    UNKNOWN
}

@Serializable
enum class TimelineEventType {
    SESSION_STARTED,
    ENROLLMENT_OPENED,
    BIOMETRIC_SERVICE_READY,
    UDFPS_UI_DISPLAYED,
    TOUCH_EVENT_OBSERVED,
    HBM_ENABLED,
    IMAGE_ACQUISITION,
    BIOMETRIC_PROCESSING,
    ENROLLMENT_PROGRESS,
    HBM_DISABLED,
    SESSION_COMPLETED,
    SESSION_FAILED,
    ERROR
}

@Serializable
enum class ObservationType {
    DIRECT_OBSERVATION,
    STATE_TRANSITION,
    CORRELATED_DEDUCTION
}

@Serializable
enum class ConfidenceLevel {
    HIGH,
    MEDIUM,
    LOW
}

@Serializable
enum class AnomalySeverity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
}

@Serializable
enum class SolutionCategory {
    GSI_ONLY_CONFIGURATION,
    GSI_ONLY_RUNTIME,
    OUTSIDE_GSI_SCOPE
}

@Serializable
enum class FeasibilityLevel {
    POSSIBLE,
    POSSIBLE_WITH_CONDITIONS,
    NOT_SUPPORTED_BY_GSI,
    INSUFFICIENT_EVIDENCE,
    UNKNOWN
}

@Serializable
enum class DiffClassification {
    IDENTICAL,
    DIFFERENT,
    MISSING,
    INACCESSIBLE,
    PARTIAL,
    INCOMPATIBLE
}

@Serializable
enum class DiffImpact {
    BENIGN,
    CRITICAL,
    INFORMATIONAL
}

@Serializable
enum class RomType {
    CUSTOM_ROM,
    GSI,
    STOCK,
    UNKNOWN
}

@Serializable
enum class SeLinuxMode {
    ENFORCING,
    PERMISSIVE,
    DISABLED,
    UNKNOWN
}

@Serializable
enum class RootState {
    NOT_CHECKED,
    NOT_AVAILABLE,
    AVAILABLE_NOT_GRANTED,
    GRANTED_VERIFIED,
    DENIED
}

@Serializable
enum class ThemePreference {
    LIGHT,
    DARK,
    SYSTEM
}

@Serializable
enum class LanguagePreference {
    SYSTEM,
    FRENCH,
    ENGLISH
}

@Serializable
data class DeviceEnvironment(
    val model: String,
    val manufacturer: String,
    val brand: String,
    val device: String,
    val hardware: String,
    val board: String,
    val socManufacturer: String,
    val socModel: String,
    val androidVersion: String,
    val sdkInt: Int,
    val securityPatch: String,
    val buildFingerprint: String,
    val buildDisplay: String,
    val isTrebleEnabled: Boolean,
    val vndkVersion: String,
    val detectedRomType: RomType,
    val romTypeEvidence: String,
    val rootState: RootState,
    val rootProviderHint: String?,
    val seLinuxMode: SeLinuxMode,
    val seLinuxContext: String?,
    val hasFingerprintFeature: Boolean,
    val biometricHardwareStatus: String,
    val civilTimestampMs: Long
)

@Serializable
data class ProbeFindingItem(
    val key: String,
    val value: String,
    val location: String,
    val discoveryStatus: DiscoveryStatus,
    val epistemicLevel: EpistemicLevel,
    val accessLevel: AccessLevel,
    val note: String? = null
)

@Serializable
data class ProbeResult(
    val probeId: String,
    val domain: ProbeDomain,
    val status: DiscoveryStatus,
    val accessLevelUsed: AccessLevel,
    val summary: String,
    val items: List<ProbeFindingItem>,
    val inaccessibleReasons: List<String> = emptyList(),
    val rawFileName: String? = null,
    val durationMs: Long,
    val civilTimestampMs: Long
)

@Serializable
data class DiscoveredComponent(
    val id: String,
    val name: String,
    val domain: ProbeDomain,
    val role: ComponentRole,
    val partition: PartitionOrigin,
    val location: String,
    val interfaces: List<String> = emptyList(),
    val discoveryStatus: DiscoveryStatus,
    val epistemicLevel: EpistemicLevel,
    val metadata: Map<String, String> = emptyMap(),
    val evidenceIds: List<String> = emptyList()
)

@Serializable
data class DependencyLink(
    val id: String,
    val fromComponentId: String,
    val toComponentId: String,
    val relationType: String,
    val expected: Boolean,
    val observed: Boolean,
    val epistemicLevel: EpistemicLevel,
    val notes: String,
    val evidenceIds: List<String> = emptyList()
)

@Serializable
data class EvidenceRecord(
    val id: String,
    val source: String,
    val resourceType: String,
    val observedValue: String,
    val civilTimestampMs: Long,
    val monotonicNanos: Long,
    val collectionMethod: String,
    val accessLevel: AccessLevel,
    val executionResult: String,
    val discoveryStatus: DiscoveryStatus,
    val epistemicLevel: EpistemicLevel,
    val rawRef: String? = null
)

@Serializable
data class TimelineEvent(
    val id: String,
    val type: TimelineEventType,
    val monotonicNanos: Long,
    val relativeMs: Long,
    val civilTimestampMs: Long,
    val source: String,
    val data: String,
    val evidenceId: String,
    val confidence: ConfidenceLevel,
    val observationType: ObservationType,
    val relatedEventIds: List<String> = emptyList()
)

@Serializable
data class CorrelationResult(
    val id: String,
    val title: String,
    val involvedComponentIds: List<String>,
    val involvedEventIds: List<String>,
    val expectedChain: String,
    val observedBehavior: String,
    val verified: Boolean,
    val unverifiableReason: String? = null,
    val epistemicLevel: EpistemicLevel,
    val evidenceIds: List<String> = emptyList()
)

@Serializable
data class AnomalyRecord(
    val id: String,
    val title: String,
    val description: String,
    val componentId: String?,
    val componentName: String,
    val severity: AnomalySeverity,
    val epistemicLevel: EpistemicLevel,
    val justifyingSources: List<String>,
    val evidenceIds: List<String>,
    val associatedEventIds: List<String> = emptyList(),
    val possibleCauses: List<String> = emptyList(),
    val missingData: List<String> = emptyList(),
    val recommendedSteps: List<String> = emptyList()
)

@Serializable
data class HypothesisRecord(
    val id: String,
    val statement: String,
    val rationale: String,
    val confidence: ConfidenceLevel,
    val supportingEvidenceIds: List<String>,
    val missingData: List<String>,
    val verificationHint: String
)

@Serializable
data class SolutionProposal(
    val id: String,
    val anomalyId: String?,
    val problemIdentified: String,
    val evidenceIds: List<String>,
    val probableCause: String,
    val componentName: String,
    val componentLocation: String,
    val partitionOrigin: PartitionOrigin,
    val dependencies: List<String>,
    val category: SolutionCategory,
    val feasibility: FeasibilityLevel,
    val technicalPrerequisites: List<String>,
    val compatibilityRisks: List<String>,
    val validationMethod: String,
    val missingInformation: List<String>,
    val presentInCustomRom: Boolean? = null,
    val presentInGsi: Boolean? = null
)

@Serializable
data class AIAnalysis(
    val id: String,
    val modelName: String,
    val thinkingLevel: String,
    val civilTimestampMs: Long,
    val summary: String,
    val anomalyExplanations: List<String>,
    val componentRelationsInsight: String,
    val missingInformationIdentified: List<String>,
    val hypothesisEvaluations: List<String>,
    val investigationLeads: List<String>,
    val gsiScopeLimitations: List<String>,
    val thoughtSummary: String? = null,
    val disclaimer: String = "Interprétation assistée par IA sur faits extraits uniquement. Ne remplace pas les preuves vérifiées."
)

@Serializable
enum class ArtifactKind {
    ELF_BINARY,
    ELF_SHARED_LIB,
    APK_DEX,
    RRO_OVERLAY,
    INIT_RC,
    VINTF_XML,
    SEPOLICY_OR_PERM,
    PROC_RUNTIME
}

@Serializable
data class DisassembledArtifact(
    val id: String,
    val name: String,
    val path: String,
    val partition: PartitionOrigin,
    val kind: ArtifactKind,
    val architecture: String? = null,
    val neededLibraries: List<String> = emptyList(),
    val keySymbols: List<String> = emptyList(),
    val extractedStrings: List<String> = emptyList(),
    val disassemblySnippet: String = "",
    val epistemicLevel: EpistemicLevel = EpistemicLevel.PROVED,
    val rawFileName: String? = null
)

@Serializable
data class ProcessRuntimeSnapshot(
    val processName: String,
    val pid: Int,
    val openFodDescriptors: List<String> = emptyList(),
    val loadedFodLibraries: List<String> = emptyList(),
    val epistemicLevel: EpistemicLevel = EpistemicLevel.PROVED
)

@Serializable
data class FodMechanismStep(
    val order: Int,
    val stageName: String,
    val componentName: String,
    val mechanismSummary: String,
    val involvedFiles: List<String> = emptyList(),
    val observedSymbolsOrCalls: List<String> = emptyList(),
    val runtimeProofs: List<String> = emptyList(),
    val epistemicLevel: EpistemicLevel,
    val verifiedInLiveTrace: Boolean = false,
    val missingInfo: String? = null
)

@Serializable
data class LiveTraceData(
    val sessionStartedMonotonicNanos: Long,
    val sessionEndedMonotonicNanos: Long,
    val durationMs: Long,
    val enrollmentOpened: Boolean,
    val enrollmentReturnedWithBiometricCheck: String,
    val observedSources: List<String>,
    val inaccessibleSources: List<String>,
    val events: List<TimelineEvent>,
    val rawBufferTruncated: Boolean = false,
    val runtimeSnapshots: List<ProcessRuntimeSnapshot> = emptyList(),
    val surfaceFlingerSnapshot: String? = null,
    val dumpsysFingerprintDelta: String? = null
)

@Serializable
data class DiagnosticSession(
    val schemaVersion: Int = FODTRACER_SCHEMA_VERSION,
    val sessionId: String,
    val label: String,
    val createdAtCivilMs: Long,
    val updatedAtCivilMs: Long,
    val environment: DeviceEnvironment,
    val probeResults: List<ProbeResult>,
    val components: List<DiscoveredComponent>,
    val dependencies: List<DependencyLink>,
    val evidence: List<EvidenceRecord>,
    val liveTrace: LiveTraceData? = null,
    val correlations: List<CorrelationResult> = emptyList(),
    val anomalies: List<AnomalyRecord> = emptyList(),
    val hypotheses: List<HypothesisRecord> = emptyList(),
    val solutions: List<SolutionProposal> = emptyList(),
    val aiAnalysis: AIAnalysis? = null,
    val rawArtifacts: Map<String, String> = emptyMap(),
    val isAnonymized: Boolean = false,
    val disassembledArtifacts: List<DisassembledArtifact> = emptyList(),
    val mechanismSteps: List<FodMechanismStep> = emptyList()
)

@Serializable
data class ComparisonCompatibility(
    val isComparable: Boolean,
    val schemaCompatible: Boolean,
    val hardwareMatchScore: Int,
    val sameDeviceOrSoc: Boolean,
    val androidVersionA: String,
    val androidVersionB: String,
    val bothHaveColdPhase: Boolean,
    val bothHaveLivePhase: Boolean,
    val warnings: List<String>
)

@Serializable
data class StructuralDiffItem(
    val id: String,
    val domain: ProbeDomain,
    val category: String,
    val key: String,
    val valueInRomA: String?,
    val valueInGsiB: String?,
    val classification: DiffClassification,
    val impact: DiffImpact,
    val rationale: String
)

@Serializable
data class BehavioralDiffItem(
    val id: String,
    val stepName: String,
    val eventType: TimelineEventType?,
    val romRelativeMs: Long?,
    val gsiRelativeMs: Long?,
    val latencyDeltaMs: Long?,
    val classification: DiffClassification,
    val impact: DiffImpact,
    val observation: String
)

@Serializable
data class ComparisonReport(
    val schemaVersion: Int = FODTRACER_SCHEMA_VERSION,
    val comparisonId: String,
    val createdAtCivilMs: Long,
    val archiveASessionId: String,
    val archiveALabel: String,
    val archiveBSessionId: String,
    val archiveBLabel: String,
    val compatibility: ComparisonCompatibility,
    val summary: String,
    val commonComponentsCount: Int,
    val structuralDiffs: List<StructuralDiffItem>,
    val behavioralDiffs: List<BehavioralDiffItem>,
    val anomaliesOnlyInRomA: List<AnomalyRecord>,
    val anomaliesOnlyInGsiB: List<AnomalyRecord>,
    val regressionHypotheses: List<HypothesisRecord>,
    val itemsToExamine: List<String>,
    val confidence: ConfidenceLevel,
    val candidateSolutions: List<SolutionProposal> = emptyList(),
    val aiAnalysis: AIAnalysis? = null
)

@Serializable
data class ArchiveManifest(
    val schemaVersion: Int = FODTRACER_SCHEMA_VERSION,
    val sessionId: String,
    val label: String,
    val createdAtCivilMs: Long,
    val appVersionName: String,
    val deviceModel: String,
    val androidVersion: String,
    val romType: RomType,
    val hasLiveTrace: Boolean,
    val isAnonymized: Boolean,
    val fileSha256: Map<String, String>,
    val totalUncompressedBytes: Long
)
