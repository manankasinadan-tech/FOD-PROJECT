package com.example.fodtracer.core.evidence

import com.example.fodtracer.domain.models.*

class EvidenceEngine {

    fun buildColdEvidence(probeResults: List<ProbeResult>): List<EvidenceRecord> {
        val records = mutableListOf<EvidenceRecord>()
        var counter = 0
        probeResults.forEach { probe ->
            probe.items.forEach { item ->
                counter += 1
                val id = "EV-COLD-${probe.domain.name}-${counter.toString().padStart(4, '0')}"
                records += EvidenceRecord(
                    id = id,
                    source = item.location,
                    resourceType = "${probe.domain.name}:${item.key}",
                    observedValue = item.value,
                    civilTimestampMs = probe.civilTimestampMs,
                    monotonicNanos = System.nanoTime(),
                    collectionMethod = probe.probeId,
                    accessLevel = item.accessLevel,
                    executionResult = probe.status.name,
                    discoveryStatus = item.discoveryStatus,
                    epistemicLevel = item.epistemicLevel,
                    rawRef = probe.rawFileName
                )
            }
            if (probe.inaccessibleReasons.isNotEmpty() && probe.items.none { it.discoveryStatus == DiscoveryStatus.INACCESSIBLE }) {
                counter += 1
                records += EvidenceRecord(
                    id = "EV-COLD-${probe.domain.name}-${counter.toString().padStart(4, '0')}",
                    source = probe.probeId,
                    resourceType = "${probe.domain.name}:ACCESS_LIMITATION",
                    observedValue = probe.inaccessibleReasons.joinToString(" | "),
                    civilTimestampMs = probe.civilTimestampMs,
                    monotonicNanos = System.nanoTime(),
                    collectionMethod = probe.probeId,
                    accessLevel = probe.accessLevelUsed,
                    executionResult = DiscoveryStatus.INACCESSIBLE.name,
                    discoveryStatus = DiscoveryStatus.INACCESSIBLE,
                    epistemicLevel = EpistemicLevel.INACCESSIBLE,
                    rawRef = probe.rawFileName
                )
            }
        }
        return records
    }

    fun attachComponentEvidenceLinks(
        components: List<DiscoveredComponent>,
        evidence: List<EvidenceRecord>
    ): List<DiscoveredComponent> {
        return components.map { component ->
            val matchingIds = evidence
                .filter { ev ->
                    ev.resourceType.startsWith(component.domain.name) &&
                        ev.discoveryStatus != DiscoveryStatus.ERROR
                }
                .map { it.id }
                .take(25)
            component.copy(evidenceIds = matchingIds)
        }
    }
}
