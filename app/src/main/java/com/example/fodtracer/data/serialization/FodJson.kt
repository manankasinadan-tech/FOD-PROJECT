package com.example.fodtracer.data.serialization

import com.example.fodtracer.domain.models.*
import kotlinx.serialization.json.Json

object FodJson {
    val codec: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        prettyPrint = true
        isLenient = false
    }
}

/**
 * Produces a non-destructive anonymized copy of a DiagnosticSession prior to sharing/export.
 * Preserves all FOD/UDFPS/GSI technical parameters while redacting device-unique identifiers.
 */
object ReportAnonymizer {

    private val SENSITIVE_PROP_PATTERNS = listOf(
        "serialno", "imei", "meid", "macaddr", "wifimac", "btmac",
        "persist.sys.device_name", "ro.boot.serialno", "ro.serialno",
        "ro.ril.oem.imei", "ro.vendor.gsi.id"
    )

    private val MAC_REGEX = Regex("\\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b")
    private val IMEI_REGEX = Regex("\\b\\d{15}\\b")

    fun anonymize(session: DiagnosticSession): DiagnosticSession {
        val redactedSessionId = "ANON-${session.sessionId.hashCode().toUInt().toString(16)}"
        val redactedEnv = session.environment.copy(
            buildFingerprint = maskToken(session.environment.buildFingerprint),
            seLinuxContext = session.environment.seLinuxContext?.let { redactString(it) }
        )

        val redactedProbes = session.probeResults.map { probe ->
            probe.copy(
                items = probe.items.map { item ->
                    val isSensitiveKey = SENSITIVE_PROP_PATTERNS.any { item.key.contains(it, ignoreCase = true) }
                    item.copy(
                        value = if (isSensitiveKey) "[REDACTED]" else redactString(item.value)
                    )
                }
            )
        }

        val redactedEvidence = session.evidence.map { ev ->
            val isSensitiveSource = SENSITIVE_PROP_PATTERNS.any {
                ev.resourceType.contains(it, ignoreCase = true) || ev.source.contains(it, ignoreCase = true)
            }
            ev.copy(
                observedValue = if (isSensitiveSource) "[REDACTED]" else redactString(ev.observedValue)
            )
        }

        val redactedLive = session.liveTrace?.copy(
            events = session.liveTrace.events.map { evt ->
                evt.copy(data = redactString(evt.data))
            },
            binderTransactions = session.liveTrace.binderTransactions.map { redactString(it) },
            tracefsEvents = session.liveTrace.tracefsEvents.map { redactString(it) },
            dumpsysDiffs = session.liveTrace.dumpsysDiffs.map { redactString(it) },
            surfaceFlingerSnapshot = session.liveTrace.surfaceFlingerSnapshot?.let { redactString(it) },
            dumpsysFingerprintDelta = session.liveTrace.dumpsysFingerprintDelta?.let { redactString(it) }
        )

        val redactedRaw = session.rawArtifacts.mapValues { (_, v) -> redactString(v) }

        return session.copy(
            sessionId = redactedSessionId,
            environment = redactedEnv,
            probeResults = redactedProbes,
            evidence = redactedEvidence,
            liveTrace = redactedLive,
            rawArtifacts = redactedRaw,
            isAnonymized = true
        )
    }

    private fun redactString(input: String): String {
        return input
            .replace(MAC_REGEX, "[REDACTED_MAC]")
            .replace(IMEI_REGEX, "[REDACTED_IMEI]")
    }

    private fun maskToken(input: String): String {
        val parts = input.split("/")
        return if (parts.size >= 4) {
            parts.mapIndexed { idx, part ->
                if (idx == 2) "[REDACTED_BUILD_ID]" else part
            }.joinToString("/")
        } else {
            redactString(input)
        }
    }
}
