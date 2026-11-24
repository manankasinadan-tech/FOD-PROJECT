package com.example.fodtracer.data.archives

import com.example.fodtracer.domain.models.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Generates a single self-contained, plain-text-readable Markdown (.md) report containing 100% of a
 * FodTracer DiagnosticSession: environment, Phase 1 probes, 6-stage causal logic, Frida-grade
 * code-correlated live timeline, binder/tracefs/procfs telemetry, anomalies, solutions, and
 * full inline disassembly listings for every APK/SO/ELF/RRO/RC/VINTF artifact.
 */
object MarkdownReportExporter {

    fun generateMarkdown(session: DiagnosticSession): String {
        val sb = StringBuilder(32_768)
        val createdUtc = formatUtc(session.createdAtCivilMs)
        val updatedUtc = formatUtc(session.updatedAtCivilMs)
        val env = session.environment

        sb.appendLine("# FodTracer — Rapport Complet d'Investigation FOD / UDFPS")
        sb.appendLine()
        sb.appendLine("- **Session ID**: `${session.sessionId}`")
        sb.appendLine("- **Label**: ${session.label}")
        sb.appendLine("- **Schema Version**: `v${session.schemaVersion}`")
        sb.appendLine("- **Créé (UTC)**: `$createdUtc` | **Mis à jour (UTC)**: `$updatedUtc`")
        sb.appendLine("- **Anonymisé**: `${session.isAnonymized}`")
        sb.appendLine("- **Phase 2 Live Trace**: `${if (session.liveTrace != null) "INCLUSE (${session.liveTrace.events.size} événements, ${session.liveTrace.durationMs}ms)" else "Non exécutée"}`")
        sb.appendLine("- **Artefacts désassemblés**: `${session.disassembledArtifacts.size}` | **Fichiers bruts inclus**: `${session.rawArtifacts.size}`")
        sb.appendLine()

        sb.appendLine("## Table des matières")
        sb.appendLine("1. [Environnement Matériel, ROM, Root & SELinux](#1-environnement-mat%C3%A9riel-rom-root--selinux)")
        sb.appendLine("2. [Sondes Phase 1 (12 Domaines)](#2-sondes-phase-1-12-domaines)")
        sb.appendLine("3. [Composants & Graphe de Dépendances](#3-composants--graphe-de-d%C3%A9pendances)")
        sb.appendLine("4. [Chaîne Causale FOD Reconstituée (6 Étapes)](#4-cha%C3%AEne-causale-fod-reconstitu%C3%A9e-6-%C3%A9tapes)")
        sb.appendLine("5. [Chronologie LIVE Corrélée au Code](#5-chronologie-live-corr%C3%A9l%C3%A9e-au-code)")
        sb.appendLine("6. [Télémétrie Système Approfondie (/proc, binder_logs, tracefs, dumpsys)](#6-t%C3%A9l%C3%A9m%C3%A9trie-syst%C3%A8me-approfondie-proc-binder_logs-tracefs-dumpsys)")
        sb.appendLine("7. [Preuves Épistémiques & Ressources Inaccessibles](#7-preuves-%C3%A9pist%C3%A9miques--ressources-inaccessibles)")
        sb.appendLine("8. [Anomalies, Corrélations & Hypothèses](#8-anomalies-corr%C3%A9lations--hypoth%C3%A8ses)")
        sb.appendLine("9. [Solutions & Analyse de Faisabilité GSI](#9-solutions--analyse-de-faisabilit%C3%A9-gsi)")
        if (session.aiAnalysis != null) {
            sb.appendLine("10. [Synthèse Assistée par IA](#10-synth%C3%A8se-assist%C3%A9e-par-ia)")
        }
        sb.appendLine("11. [Désassemblage Complet & Listings Bruts](#11-d%C3%A9sassemblage-complet--listings-bruts)")
        sb.appendLine()
        sb.appendLine("---")
        sb.appendLine()

        // 1. Environment
        sb.appendLine("## 1. Environnement Matériel, ROM, Root & SELinux")
        sb.appendLine()
        sb.appendLine("| Champ | Valeur |")
        sb.appendLine("|---|---|")
        sb.appendLine("| Appareil / Modèle | `${env.manufacturer} ${env.model}` (`${env.brand} / ${env.device}`) |")
        sb.appendLine("| Hardware / Board | `${env.hardware}` / `${env.board}` |")
        sb.appendLine("| SoC | `${env.socManufacturer} ${env.socModel}` |")
        sb.appendLine("| Android / SDK / Patch | `Android ${env.androidVersion}` (API `${env.sdkInt}`) • Patch `${env.securityPatch}` |")
        sb.appendLine("| Build Fingerprint | `${env.buildFingerprint}` |")
        sb.appendLine("| Build Display | `${env.buildDisplay}` |")
        sb.appendLine("| Treble / VNDK | `Treble=${env.isTrebleEnabled}` • `VNDK=${env.vndkVersion}` |")
        sb.appendLine("| Type ROM détecté | `${env.detectedRomType}` (${env.romTypeEvidence}) |")
        sb.appendLine("| ROOT (su) | `${env.rootState}` (${env.rootProviderHint ?: "none"}) |")
        sb.appendLine("| SELinux | `${env.seLinuxMode}` • `${env.seLinuxContext ?: "unknown"}` |")
        sb.appendLine("| Feature Fingerprint / Biometric API | `hasFeature=${env.hasFingerprintFeature}` • `${env.biometricHardwareStatus}` |")
        sb.appendLine()

        // 2. Phase 1 Probes
        sb.appendLine("## 2. Sondes Phase 1 (12 Domaines)")
        sb.appendLine()
        session.probeResults.forEach { probe ->
            sb.appendLine("### Domaine `${probe.domain.name}` (`${probe.probeId}`) — `${probe.status.name}`")
            sb.appendLine("- **Niveau d'accès**: `${probe.accessLevelUsed.name}` | **Durée**: `${probe.durationMs}ms`")
            sb.appendLine("- **Résumé**: ${probe.summary}")
            if (probe.inaccessibleReasons.isNotEmpty()) {
                sb.appendLine("- **Raisons d'inaccessibilité**: ${probe.inaccessibleReasons.joinToString("; ")}")
            }
            if (probe.items.isNotEmpty()) {
                sb.appendLine()
                sb.appendLine("| Clé | Valeur | Emplacement | Statut | Épistémique |")
                sb.appendLine("|---|---|---|---|---|")
                probe.items.forEach { item ->
                    sb.appendLine(
                        "| `${escMd(item.key)}` | `${escMd(item.value)}` | `${escMd(item.location)}` | `${item.discoveryStatus.name}` | `${item.epistemicLevel.name}` |"
                    )
                }
            }
            sb.appendLine()
        }

        // 3. Components & Dependencies
        sb.appendLine("## 3. Composants & Graphe de Dépendances")
        sb.appendLine()
        sb.appendLine("### Composants découverts (${session.components.size})")
        if (session.components.isEmpty()) {
            sb.appendLine("_Aucun composant synthétisé._")
        } else {
            sb.appendLine("| ID | Composant | Rôle | Partition | Emplacement | Statut | Épistémique |")
            sb.appendLine("|---|---|---|---|---|---|---|")
            session.components.forEach { c ->
                sb.appendLine("| `${c.id}` | ${escMd(c.name)} | `${c.role.name}` | `${c.partition.name}` | `${escMd(c.location)}` | `${c.discoveryStatus.name}` | `${c.epistemicLevel.name}` |")
            }
        }
        sb.appendLine()
        sb.appendLine("### Liens de dépendance (${session.dependencies.size})")
        if (session.dependencies.isEmpty()) {
            sb.appendLine("_Aucun lien de dépendance enregistré._")
        } else {
            session.dependencies.forEach { link ->
                sb.appendLine("- **`${link.id}` `${link.relationType}`** (`${link.fromComponentId}` -> `${link.toComponentId}`) • Observé=`${link.observed}` • `${link.epistemicLevel.name}`: ${link.notes}")
            }
        }
        sb.appendLine()

        // 4. 6-Stage Causal FOD Logic
        sb.appendLine("## 4. Chaîne Causale FOD Reconstituée (6 Étapes)")
        sb.appendLine()
        if (session.mechanismSteps.isEmpty()) {
            sb.appendLine("_Aucune étape reconstituée._")
        } else {
            session.mechanismSteps.forEach { step ->
                sb.appendLine("### ${step.stageName} — `[${step.epistemicLevel.name}]`")
                sb.appendLine("- **Composant**: ${step.componentName}")
                sb.appendLine("- **Vérifié en Live**: `${step.verifiedInLiveTrace}`")
                sb.appendLine("- **Mécanisme**: ${step.mechanismSummary}")
                if (step.involvedFiles.isNotEmpty()) {
                    sb.appendLine("- **Fichiers impliqués**: ${step.involvedFiles.joinToString(", ") { "`$it`" }}")
                }
                if (step.observedSymbolsOrCalls.isNotEmpty()) {
                    sb.appendLine("- **Symboles / Appels / Valeurs**:")
                    step.observedSymbolsOrCalls.forEach { sb.appendLine("  - `$it`") }
                }
                if (step.runtimeProofs.isNotEmpty()) {
                    sb.appendLine("- **Preuves Runtime**:")
                    step.runtimeProofs.forEach { sb.appendLine("  - `$it`") }
                }
                step.missingInfo?.let { sb.appendLine("- **Information manquante**: _${it}_") }
                sb.appendLine()
            }
        }

        // 5. Code-Correlated Live Timeline
        sb.appendLine("## 5. Chronologie LIVE Corrélée au Code")
        sb.appendLine()
        val live = session.liveTrace
        if (live == null) {
            sb.appendLine("_Phase 2 Live Tracer non exécutée pour cette session._")
            sb.appendLine()
        } else {
            sb.appendLine("- **Durée**: `${live.durationMs}ms` | **Enrôlement ouvert**: `${live.enrollmentOpened}`")
            sb.appendLine("- **Vérification BiometricManager post-retour**: `${live.enrollmentReturnedWithBiometricCheck}`")
            sb.appendLine("- **Sources observées (${live.observedSources.size})**: ${live.observedSources.joinToString(", ") { "`$it`" }}")
            sb.appendLine("- **Tampon tronqué**: `${live.rawBufferTruncated}`")
            sb.appendLine()
            if (live.events.isEmpty()) {
                sb.appendLine("_Aucun événement capturé._")
            } else {
                live.events.forEach { evt ->
                    sb.appendLine("#### `+${evt.relativeMs}ms` `${evt.type.name}` (`${evt.id}`)")
                    sb.appendLine("- **Source**: `${evt.source}` | **Type**: `${evt.observationType.name}` | **Confiance**: `${evt.confidence.name}` | **Monotone**: `${evt.monotonicNanos}ns`")
                    sb.appendLine("- **Télémétrie**: `${evt.data}`")
                    evt.procStateNote?.let { sb.appendLine("- **État Processus (/proc)**: `$it`") }
                    if (evt.codeRefs.isNotEmpty()) {
                        sb.appendLine("- **Code / Binaire corrélé**:")
                        evt.codeRefs.forEach { ref ->
                            sb.appendLine("  - **`${ref.artifactPath}`** -> `${ref.symbolOrMethod}`" + (ref.targetResource?.let { " (cible: `$it`)" } ?: ""))
                            ref.callerChain.forEach { chain ->
                                sb.appendLine("    - Chaîne Xref: `$chain`")
                            }
                        }
                    }
                    sb.appendLine()
                }
            }
        }

        // 6. Deep Root Read-Only Telemetry
        sb.appendLine("## 6. Télémétrie Système Approfondie (/proc, binder_logs, tracefs, dumpsys)")
        sb.appendLine()
        if (live != null) {
            if (live.runtimeSnapshots.isNotEmpty()) {
                sb.appendLine("### Instantanés Processus (`/proc/<pid>`)")
                live.runtimeSnapshots.forEach { snap ->
                    sb.appendLine("#### `${snap.processName}` (PID `${snap.pid}`)")
                    snap.wchan?.let { sb.appendLine("- **wchan**: `$it`") }
                    snap.syscall?.let { sb.appendLine("- **syscall**: `$it`") }
                    if (snap.kernelStack.isNotEmpty()) {
                        sb.appendLine("- **Kernel Stack (`/proc/${snap.pid}/stack`)**:")
                        sb.appendLine("```")
                        snap.kernelStack.forEach { sb.appendLine(it) }
                        sb.appendLine("```")
                    }
                    if (snap.openFodDescriptors.isNotEmpty()) {
                        sb.appendLine("- **Descripteurs ouverts (`/proc/${snap.pid}/fd`)**:")
                        sb.appendLine("```")
                        snap.openFodDescriptors.forEach { sb.appendLine(it) }
                        sb.appendLine("```")
                    }
                    if (snap.loadedFodLibraries.isNotEmpty()) {
                        sb.appendLine("- **Bibliothèques & APKs mappés (`/proc/${snap.pid}/maps`)**:")
                        snap.loadedFodLibraries.forEach { sb.appendLine("  - `$it`") }
                    }
                    sb.appendLine()
                }
            }
            if (live.binderTransactions.isNotEmpty()) {
                sb.appendLine("### Transactions `binder_logs` observées (${live.binderTransactions.size})")
                sb.appendLine("```")
                live.binderTransactions.forEach { sb.appendLine(it) }
                sb.appendLine("```")
                sb.appendLine()
            }
            if (live.tracefsEvents.isNotEmpty()) {
                sb.appendLine("### Événements `tracefs` passifs observés (${live.tracefsEvents.size})")
                sb.appendLine("```")
                live.tracefsEvents.forEach { sb.appendLine(it) }
                sb.appendLine("```")
                sb.appendLine()
            }
            live.surfaceFlingerSnapshot?.let { sf ->
                sb.appendLine("### Snapshot `dumpsys SurfaceFlinger`")
                sb.appendLine("```")
                sb.appendLine(sf)
                sb.appendLine("```")
                sb.appendLine()
            }
            live.dumpsysFingerprintDelta?.let { fp ->
                sb.appendLine("### Delta `dumpsys fingerprint`")
                sb.appendLine("```")
                sb.appendLine(fp)
                sb.appendLine("```")
                sb.appendLine()
            }
            if (live.dumpsysDiffs.isNotEmpty()) {
                sb.appendLine("### Différentiels `dumpsys` (biometric/display/input/SurfaceFlinger)")
                sb.appendLine("```")
                live.dumpsysDiffs.forEach { sb.appendLine(it) }
                sb.appendLine("```")
                sb.appendLine()
            }
        } else {
            sb.appendLine("_Aucune capture live disponible._")
            sb.appendLine()
        }

        // 7. Evidence & Inaccessible
        sb.appendLine("## 7. Preuves Épistémiques & Ressources Inaccessibles")
        sb.appendLine()
        val inaccessibleLive = live?.inaccessibleSources.orEmpty()
        val inaccessibleEv = session.evidence.filter { it.epistemicLevel == EpistemicLevel.INACCESSIBLE }
        if (inaccessibleLive.isNotEmpty() || inaccessibleEv.isNotEmpty()) {
            sb.appendLine("### Sources `INACCESSIBLE` (jamais supposées inexistantes)")
            inaccessibleLive.forEach { sb.appendLine("- `[LIVE]` `$it`") }
            inaccessibleEv.forEach { sb.appendLine("- `[${it.id}]` `${it.source}`: ${it.observedValue}") }
            sb.appendLine()
        }
        val provedEv = session.evidence.filter { it.epistemicLevel == EpistemicLevel.PROVED }
        sb.appendLine("### Faits `PROVED` (${provedEv.size})")
        provedEv.forEach { ev ->
            sb.appendLine("- **`${ev.id}`** (`${ev.resourceType}`, `${ev.accessLevel.name}`, `${ev.source}`): `${ev.observedValue}`")
        }
        sb.appendLine()

        // 8. Anomalies, Correlations & Hypotheses
        sb.appendLine("## 8. Anomalies, Corrélations & Hypothèses")
        sb.appendLine()
        sb.appendLine("### Anomalies (${session.anomalies.size})")
        if (session.anomalies.isEmpty()) {
            sb.appendLine("_Aucune anomalie prouvée détectée._")
        } else {
            session.anomalies.forEach { a ->
                sb.appendLine("- **`${a.id}` [${a.severity.name} / ${a.epistemicLevel.name}] ${a.title}** (`${a.componentName}`)")
                sb.appendLine("  - Description: ${a.description}")
                if (a.possibleCauses.isNotEmpty()) sb.appendLine("  - Causes possibles: ${a.possibleCauses.joinToString("; ")}")
                if (a.recommendedSteps.isNotEmpty()) sb.appendLine("  - Vérifications suggérées: ${a.recommendedSteps.joinToString("; ")}")
            }
        }
        sb.appendLine()
        sb.appendLine("### Corrélations (${session.correlations.size})")
        session.correlations.forEach { c ->
            sb.appendLine("- **`${c.id}` [${c.epistemicLevel.name}] ${c.title}**")
            sb.appendLine("  - Attendu: ${c.expectedChain}")
            sb.appendLine("  - Observé: ${c.observedBehavior}")
            c.unverifiableReason?.let { sb.appendLine("  - Limite: $it") }
        }
        sb.appendLine()
        sb.appendLine("### Hypothèses (${session.hypotheses.size})")
        session.hypotheses.forEach { h ->
            sb.appendLine("- **`${h.id}` [${h.confidence.name}] ${h.statement}**")
            sb.appendLine("  - Raisonnement: ${h.rationale}")
            if (h.missingData.isNotEmpty()) sb.appendLine("  - Données manquantes: ${h.missingData.joinToString("; ")}")
            sb.appendLine("  - Test de vérification: ${h.verificationHint}")
        }
        sb.appendLine()

        // 9. GSI Solutions
        sb.appendLine("## 9. Solutions & Analyse de Faisabilité GSI")
        sb.appendLine()
        if (session.solutions.isEmpty()) {
            sb.appendLine("_Aucune proposition de solution générée._")
        } else {
            session.solutions.forEach { s ->
                sb.appendLine("### `${s.id}` [${s.category.name} | ${s.feasibility.name}] — ${s.problemIdentified}")
                sb.appendLine("- **Composant**: `${s.componentName}` (`${s.componentLocation}`, `${s.partitionOrigin.name}`)")
                sb.appendLine("- **Cause probable**: ${s.probableCause}")
                if (s.technicalPrerequisites.isNotEmpty()) sb.appendLine("- **Prérequis**: ${s.technicalPrerequisites.joinToString("; ")}")
                if (s.compatibilityRisks.isNotEmpty()) sb.appendLine("- **Risques**: ${s.compatibilityRisks.joinToString("; ")}")
                sb.appendLine("- **Méthode de validation**: ${s.validationMethod}")
                sb.appendLine()
            }
        }

        // 10. AI Analysis
        session.aiAnalysis?.let { ai ->
            sb.appendLine("## 10. Synthèse Assistée par IA")
            sb.appendLine("- **Modèle**: `${ai.modelName}` | **Thinking**: `${ai.thinkingLevel}`")
            sb.appendLine("- **Avertissement**: _${ai.disclaimer}_")
            sb.appendLine()
            sb.appendLine(ai.summary)
            if (ai.investigationLeads.isNotEmpty()) {
                sb.appendLine()
                sb.appendLine("**Pistes d'investigation :**")
                ai.investigationLeads.forEach { sb.appendLine("- $it") }
            }
            sb.appendLine()
        }

        // 11. Complete Disassembly Listings
        sb.appendLine("## 11. Désassemblage Complet & Listings Bruts")
        sb.appendLine()
        val emittedRawKeys = HashSet<String>()
        if (session.disassembledArtifacts.isEmpty() && session.rawArtifacts.isEmpty()) {
            sb.appendLine("_Aucun artefact désassemblé extrait pour cette session._")
        } else {
            session.disassembledArtifacts.forEach { art ->
                sb.appendLine("### `${art.id}` ${art.name} (`${art.kind.name}` • `${art.partition.name}`)")
                sb.appendLine("- **Chemin**: `${art.path}`")
                art.architecture?.let { sb.appendLine("- **Architecture**: `$it`") }
                sb.appendLine("- **Statut épistémique**: `${art.epistemicLevel.name}`")
                if (art.neededLibraries.isNotEmpty()) {
                    sb.appendLine("- **Dépendances / DEX (`DT_NEEDED`)**: ${art.neededLibraries.joinToString(", ") { "`$it`" }}")
                }
                if (art.decodedResources.isNotEmpty()) {
                    sb.appendLine("- **Ressources décodées (`AXML` / `resources.arsc`)**:")
                    art.decodedResources.forEach { sb.appendLine("  - `$it`") }
                }
                if (art.crossReferences.isNotEmpty()) {
                    sb.appendLine("- **Références croisées (Appels -> Cibles)**:")
                    art.crossReferences.forEach { sb.appendLine("  - `$it`") }
                }
                if (art.keySymbols.isNotEmpty()) {
                    sb.appendLine("- **Symboles / Classes clés (${art.keySymbols.size})**:")
                    art.keySymbols.forEach { sb.appendLine("  - `$it`") }
                }
                if (art.extractedStrings.isNotEmpty()) {
                    sb.appendLine("- **Chaînes / Descripteurs extraits (${art.extractedStrings.size})**:")
                    art.extractedStrings.forEach { sb.appendLine("  - `$it`") }
                }
                val rawBody = art.rawFileName?.let { key ->
                    emittedRawKeys += key
                    session.rawArtifacts[key]
                } ?: art.disassemblySnippet

                if (rawBody.isNotBlank()) {
                    sb.appendLine()
                    sb.appendLine("**Listing complet (`${art.rawFileName ?: art.path}`) :**")
                    sb.appendLine("```")
                    sb.appendLine(rawBody.trimEnd())
                    sb.appendLine("```")
                }
                sb.appendLine()
            }

            // Include any additional raw artifacts not directly attached to an artifact card
            session.rawArtifacts.forEach { (key, body) ->
                if (key !in emittedRawKeys && body.isNotBlank()) {
                    sb.appendLine("### Artefact brut : `$key`")
                    sb.appendLine("```")
                    sb.appendLine(body.trimEnd())
                    sb.appendLine("```")
                    sb.appendLine()
                }
            }
        }

        return sb.toString()
    }

    private fun escMd(raw: String): String =
        raw.replace("|", "\\|").replace("\n", " ").replace("\r", "")

    private fun formatUtc(ms: Long): String {
        val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        return sdf.format(Date(ms))
    }
}
