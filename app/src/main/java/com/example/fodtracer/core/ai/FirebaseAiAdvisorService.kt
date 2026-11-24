package com.example.fodtracer.core.ai

import android.content.Context
import android.util.Log
import com.example.fodtracer.domain.interfaces.AiAdvisorService
import com.example.fodtracer.domain.models.*
import com.google.firebase.Firebase
import com.google.firebase.FirebaseApp
import com.google.firebase.ai.ai
import com.google.firebase.ai.type.Schema
import com.google.firebase.ai.type.ThinkingLevel
import com.google.firebase.ai.type.generationConfig
import com.google.firebase.ai.type.thinkingConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

private const val TAG = "AiAdvisorService"
private const val MODEL_NAME = "gemini-3.8-flash"

class FirebaseAiAdvisorService(
    private val context: Context
) : AiAdvisorService {

    private val aiSchema = Schema.obj(
        properties = mapOf(
            "summary" to Schema.string(description = "Concise engineering synthesis strictly grounded in provided evidence"),
            "anomalyExplanations" to Schema.array(Schema.string(), description = "Technical explanations for observed anomalies"),
            "componentRelationsInsight" to Schema.string(description = "Analysis of component interactions and break points"),
            "missingInformationIdentified" to Schema.array(Schema.string(), description = "Data gaps preventing full causal proof"),
            "hypothesisEvaluations" to Schema.array(Schema.string(), description = "Evaluation of existing hypotheses without promoting them to proved facts"),
            "investigationLeads" to Schema.array(Schema.string(), description = "Concrete non-destructive next investigation steps"),
            "gsiScopeLimitations" to Schema.array(Schema.string(), description = "Technical boundaries separating GSI-only fixes from vendor/kernel scope")
        )
    )

    private val model by lazy {
        val config = generationConfig {
            responseMimeType = "application/json"
            responseSchema = aiSchema
            thinkingConfig = thinkingConfig {
                thinkingLevel = ThinkingLevel.HIGH
                includeThoughts = true
            }
            // Intentionally do NOT set maxOutputTokens when using ThinkingLevel.HIGH.
        }
        Firebase.ai.generativeModel(
            modelName = MODEL_NAME,
            generationConfig = config
        )
    }

    override fun isFirebaseConfigured(): Boolean {
        return runCatching {
            if (FirebaseApp.getApps(context).isEmpty()) {
                FirebaseApp.initializeApp(context) != null
            } else {
                true
            }
        }.getOrDefault(false)
    }

    override suspend fun analyzeDiagnostic(session: DiagnosticSession): Result<AIAnalysis> {
        if (!isFirebaseConfigured()) {
            return Result.failure(
                IllegalStateException("Firebase AI Logic is not configured in this build. Offline deterministic engines remain fully operational.")
            )
        }
        val prompt = buildDiagnosticPrompt(session)
        return executeStructuredReasoning(prompt)
    }

    override suspend fun analyzeComparison(report: ComparisonReport): Result<AIAnalysis> {
        if (!isFirebaseConfigured()) {
            return Result.failure(
                IllegalStateException("Firebase AI Logic is not configured in this build. Offline deterministic engines remain fully operational.")
            )
        }
        val prompt = buildComparisonPrompt(report)
        return executeStructuredReasoning(prompt)
    }

    private suspend fun executeStructuredReasoning(prompt: String): Result<AIAnalysis> {
        return try {
            val response = withTimeout(60_000L) {
                model.generateContent(prompt)
            }
            val rawJson = response.text
                ?: return Result.failure(IllegalStateException("AI model returned an empty response."))

            val obj = Json.parseToJsonElement(rawJson).jsonObject
            val thoughtSummary = response.candidates.firstOrNull()?.content?.parts
                ?.filter { it.javaClass.simpleName.contains("Thought", ignoreCase = true) }
                ?.joinToString("\n") { it.toString() }
                ?.takeIf { it.isNotBlank() }

            val analysis = AIAnalysis(
                id = "AI-${System.currentTimeMillis()}",
                modelName = MODEL_NAME,
                thinkingLevel = "HIGH",
                civilTimestampMs = System.currentTimeMillis(),
                summary = obj["summary"]?.jsonPrimitive?.content.orEmpty(),
                anomalyExplanations = obj["anomalyExplanations"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty(),
                componentRelationsInsight = obj["componentRelationsInsight"]?.jsonPrimitive?.content.orEmpty(),
                missingInformationIdentified = obj["missingInformationIdentified"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty(),
                hypothesisEvaluations = obj["hypothesisEvaluations"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty(),
                investigationLeads = obj["investigationLeads"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty(),
                gsiScopeLimitations = obj["gsiScopeLimitations"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty(),
                thoughtSummary = thoughtSummary
            )
            Result.success(analysis)
        } catch (e: TimeoutCancellationException) {
            Log.e(TAG, "AI analysis timed out after 60s", e)
            Result.failure(IllegalStateException("AI analysis timed out after 60 seconds."))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "AI analysis failed", e)
            Result.failure(e)
        }
    }

    private fun buildDiagnosticPrompt(session: DiagnosticSession): String = buildString {
        appendLine("You are FodTracer AI Advisor, an Android UDFPS/FOD and GSI systems specialist.")
        appendLine("STRICT RULES:")
        appendLine("1. NEVER invent logs, properties, HAL interfaces, sysfs paths, or evidence.")
        appendLine("2. NEVER turn a hypothesis or inaccessible probe into a proved fact.")
        appendLine("3. Base all reasoning exclusively on the structured facts below.")
        appendLine()
        appendLine("=== DEVICE ENVIRONMENT ===")
        appendLine("Model=${session.environment.manufacturer} ${session.environment.model}, SoC=${session.environment.socModel}, Android=${session.environment.androidVersion} (SDK ${session.environment.sdkInt}), ROM=${session.environment.detectedRomType}, Root=${session.environment.rootState}, SELinux=${session.environment.seLinuxMode}")
        appendLine("BiometricAPI=${session.environment.biometricHardwareStatus}")
        appendLine()
        appendLine("=== DISCOVERED COMPONENTS (${session.components.size}) ===")
        session.components.forEach {
            appendLine("- [${it.role}] ${it.name} status=${it.discoveryStatus} epistemic=${it.epistemicLevel} partition=${it.partition} loc=${it.location}")
        }
        appendLine()
        appendLine("=== CORRELATIONS ===")
        session.correlations.forEach {
            appendLine("- ${it.title}: verified=${it.verified}, observed=${it.observedBehavior}, reason=${it.unverifiableReason ?: "none"}")
        }
        appendLine()
        appendLine("=== ANOMALIES (${session.anomalies.size}) ===")
        session.anomalies.forEach {
            appendLine("- [${it.severity}/${it.epistemicLevel}] ${it.title}: ${it.description} (missing=${it.missingData})")
        }
        appendLine()
        appendLine("=== HYPOTHESES (${session.hypotheses.size}) ===")
        session.hypotheses.forEach {
            appendLine("- [${it.confidence}] ${it.statement} | missing=${it.missingData}")
        }
        appendLine()
        appendLine("=== LIVE TIMELINE (${session.liveTrace?.events?.size ?: 0} events) ===")
        session.liveTrace?.events?.take(40)?.forEach {
            appendLine("- +${it.relativeMs}ms ${it.type} (${it.source}): ${it.data.take(120)}")
        }
        appendLine()
        appendLine("=== DETERMINISTIC SOLUTION CANDIDATES ===")
        session.solutions.forEach {
            appendLine("- [${it.category}/${it.feasibility}] ${it.problemIdentified} -> ${it.probableCause}")
        }
    }

    private fun buildComparisonPrompt(report: ComparisonReport): String = buildString {
        appendLine("You are FodTracer AI Advisor analyzing a Custom ROM vs GSI FOD comparison.")
        appendLine("STRICT RULES: Do NOT fabricate missing data. Respect INACCESSIBLE vs MISSING distinctions.")
        appendLine()
        appendLine("Archive A (Reference Custom ROM): ${report.archiveALabel} | Android ${report.compatibility.androidVersionA}")
        appendLine("Archive B (GSI Under Test): ${report.archiveBLabel} | Android ${report.compatibility.androidVersionB}")
        appendLine("Compatibility score=${report.compatibility.hardwareMatchScore}, warnings=${report.compatibility.warnings}")
        appendLine()
        appendLine("=== CRITICAL STRUCTURAL DIFFS ===")
        report.structuralDiffs.filter { it.impact == DiffImpact.CRITICAL }.take(25).forEach {
            appendLine("- [${it.domain}/${it.classification}] ${it.key}: ROM='${it.valueInRomA}' vs GSI='${it.valueInGsiB}'")
        }
        appendLine()
        appendLine("=== BEHAVIORAL DIFFS ===")
        report.behavioralDiffs.forEach {
            appendLine("- ${it.stepName}: ${it.classification} (${it.impact}) ROM=${it.romRelativeMs}ms vs GSI=${it.gsiRelativeMs}ms -> ${it.observation}")
        }
        appendLine()
        appendLine("=== GSI-ONLY ANOMALIES ===")
        report.anomaliesOnlyInGsiB.forEach {
            appendLine("- [${it.severity}] ${it.title}: ${it.description}")
        }
    }
}
