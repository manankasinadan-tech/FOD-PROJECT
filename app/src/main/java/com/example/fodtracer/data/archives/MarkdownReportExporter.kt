package com.example.fodtracer.data.archives

import com.example.fodtracer.domain.models.*
import java.io.StringWriter
import java.io.Writer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Generates a single self-contained, plain-text-readable Markdown (.md) report containing 100% of a
 * FodTracer DiagnosticSession: environment, Phase 1 probes, 6-stage causal logic, Frida-grade
 * code-correlated live timeline, binder/tracefs/procfs telemetry, anomalies, solutions, and
 * full inline disassembly listings for every APK/SO/ELF/RRO/RC/VINTF artifact.
 *
 * Streams directly to a [Writer] to avoid allocating giant intermediate strings in memory.
 */
object MarkdownReportExporter {

    fun generateMarkdown(session: DiagnosticSession): String {
        val sw = StringWriter(32_768)
        writeMarkdown(session, sw)
        return sw.toString()
    }

    fun writeMarkdown(
        session: DiagnosticSession,
        writer: Writer,
        diskRawResolver: ((String) -> String?)? = null
    ) {
        fun line(text: String = "") {
            writer.write(text)
            writer.write("\n")
        }

        val createdUtc = formatUtc(session.createdAtCivilMs)
        val updatedUtc = formatUtc(session.updatedAtCivilMs)
        val env = session.environment

        line("# FodTracer — Rapport Complet d'Investigation FOD / UDFPS")
        line()
        line("- **Session ID**: `${session.sessionId}`")
        line("- **Label**: ${session.label}")
        line("- **Schema Version**: `v${session.schemaVersion}`")
        line("- **Créé (UTC)**: `$createdUtc` | **Mis à jour (UTC)**: `$updatedUtc`")
        line("- **Anonymisé**: `${session.isAnonymized}`")
        line("- **Phase 2 Live Trace**: `${if (session.liveTrace != null) "INCLUSE (${session.liveTrace.events.size} événements, ${session.liveTrace.durationMs}ms)" else "Non exécutée"}`")
        line("- **Artefacts désassemblés**: `${session.disassembledArtifacts.size}` | **Fichiers bruts inclus**: `${session.rawArtifacts.size}`")
        line()

        line("## Table des matières")
        line("1. [Environnement Matériel, ROM, Root & SELinux](#1-environnement-mat%C3%A9riel-rom-root--selinux)")
        line("2. [Sondes Phase 1 (12 Domaines)](#2-sondes-phase-1-12-domaines)")
        line("3. [Composants & Graphe de Dépendances](#3-composants--graphe-de-d%C3%A9pendances)")
        line("4. [Chaîne Causale FOD Reconstituée (6 Étapes)](#4-cha%C3%AEne-causale-fod-reconstitu%C3%A9e-6-%C3%A9tapes)")
        line("5. [Chronologie LIVE Corrélée au Code](#5-chronologie-live-corr%C3%A9l%C3%A9e-au-code)")
        line("6. [Télémétrie Système Approfondie (/proc, binder_logs, tracefs, dumpsys)](#6-t%C3%A9l%C3%A9m%C3%A9trie-syst%C3%A8me-approfondie-proc-binder_logs-tracefs-dumpsys)")
        line("7. [Preuves Épistémiques & Ressources Inaccessibles](#7-preuves-%C3%A9pist%C3%A9miques--ressources-inaccessibles)")
        line("8. [Anomalies, Corrélations & Hypothèses](#8-anomalies-corr%C3%A9lations--hypoth%C3%A8ses)")
        line("9. [Solutions & Analyse de Faisabilité GSI](#9-solutions--analyse-de-faisabilit%C3%A9-gsi)")
        if (session.aiAnalysis != null) {
            line("10. [Synthèse Assistée par IA](#10-synth%C3%A8se-assist%C3%A9e-par-ia)")
        }
        line("11. [Désassemblage Complet & Listings Bruts](#11-d%C3%A9sassemblage-complet--listings-bruts)")
        line()
        line("---")
        line()

        // 1. Environment
        line("## 1. Environnement Matériel, ROM, Root & SELinux")
        line()
        line("| Champ | Valeur |")
        line("|---|---|")
        line("| Appareil / Modèle | `${env.manufacturer} ${env.model}` (`${env.brand} / ${env.device}`) |")
        line("| Hardware / Board | `${env.hardware}` / `${env.board}` |")
        line("| SoC | `${env.socManufacturer} ${env.socModel}` |")
        line("| Android / SDK / Patch | `Android ${env.androidVersion}` (API `${env.sdkInt}`) • Patch `${env.securityPatch}` |")
        line("| Build Fingerprint | `${env.buildFingerprint}` |")
        line("| Build Display | `${env.buildDisplay}` |")
        line("| Treble / VNDK | `Treble=${env.isTrebleEnabled}` • `VNDK=${env.vndkVersion}` |")
        line("| Type ROM détecté | `${env.detectedRomType}` (${env.romTypeEvidence}) |")
        line("| ROOT (su) | `${env.rootState}` (${env.rootProviderHint ?: "none"}) |")
        line("| SELinux | `${env.seLinuxMode}` • `${env.seLinuxContext ?: "unknown"}` |")
        line("| Feature Fingerprint / Biometric API | `hasFeature=${env.hasFingerprintFeature}` • `${env.biometricHardwareStatus}` |")
        line()

        // 2. Phase 1 Probes
        line("## 2. Sondes Phase 1 (12 Domaines)")
        line()
        session.probeResults.forEach { probe ->
            line("### Domaine `${probe.domain.name}` (`${probe.probeId}`) — `${probe.status.name}`")
            line("- **Niveau d'accès**: `${probe.accessLevelUsed.name}` | **Durée**: `${probe.durationMs}ms`")
            line("- **Résumé**: ${probe.summary}")
            if (probe.inaccessibleReasons.isNotEmpty()) {
                line("- **Raisons d'inaccessibilité**: ${probe.inaccessibleReasons.joinToString("; ")}")
            }
            if (probe.items.isNotEmpty()) {
                line()
                line("| Clé | Valeur | Emplacement | Statut | Épistémique |")
                line("|---|---|---|---|---|")
                probe.items.forEach { item ->
                    line(
                        "| `${escMd(item.key)}` | `${escMd(item.value)}` | `${escMd(item.location)}` | `${item.discoveryStatus.name}` | `${item.epistemicLevel.name}` |"
                    )
                }
            }
            line()
        }

        // 3. Components & Dependencies
        line("## 3. Composants & Graphe de Dépendances")
        line()
        line("### Composants découverts (${session.components.size})")
        if (session.components.isEmpty()) {
            line("_Aucun composant synthétisé._")
        } else {
            line("| ID | Composant | Rôle | Partition | Emplacement | Statut | Épistémique |")
            line("|---|---|---|---|---|---|---|")
            session.components.forEach { c ->
                line("| `${c.id}` | ${escMd(c.name)} | `${c.role.name}` | `${c.partition.name}` | `${escMd(c.location)}` | `${c.discoveryStatus.name}` | `${c.epistemicLevel.name}` |")
            }
        }
        line()
        line("### Liens de dépendance (${session.dependencies.size})")
        if (session.dependencies.isEmpty()) {
            line("_Aucun lien de dépendance enregistré._")
        } else {
            session.dependencies.forEach { link ->
                line("- **`${link.id}` `${link.relationType}`** (`${link.fromComponentId}` -> `${link.toComponentId}`) • Observé=`${link.observed}` • `${link.epistemicLevel.name}`: ${link.notes}")
            }
        }
        line()

        // 4. 6-Stage Causal FOD Logic
        line("## 4. Chaîne Causale FOD Reconstituée (6 Étapes)")
        line()
        if (session.mechanismSteps.isEmpty()) {
            line("_Aucune étape reconstituée._")
        } else {
            session.mechanismSteps.forEach { step ->
                line("### ${step.stageName} — `[${step.epistemicLevel.name}]`")
                line("- **Composant**: ${step.componentName}")
                line("- **Vérifié en Live**: `${step.verifiedInLiveTrace}`")
                line("- **Mécanisme**: ${step.mechanismSummary}")
                if (step.involvedFiles.isNotEmpty()) {
                    line("- **Fichiers impliqués**: ${step.involvedFiles.joinToString(", ") { "`$it`" }}")
                }
                if (step.observedSymbolsOrCalls.isNotEmpty()) {
                    line("- **Symboles / Appels / Valeurs**:")
                    step.observedSymbolsOrCalls.forEach { line("  - `$it`") }
                }
                if (step.runtimeProofs.isNotEmpty()) {
                    line("- **Preuves Runtime**:")
                    step.runtimeProofs.forEach { line("  - `$it`") }
                }
                step.missingInfo?.let { line("- **Information manquante**: _${it}_") }
                line()
            }
        }

        // 5. Code-Correlated Live Timeline
        line("## 5. Chronologie LIVE Corrélée au Code")
        line()
        val live = session.liveTrace
        if (live == null) {
            line("_Phase 2 Live Tracer non exécutée pour cette session._")
            line()
        } else {
            line("- **Durée**: `${live.durationMs}ms` | **Enrôlement ouvert**: `${live.enrollmentOpened}`")
            line("- **Vérification BiometricManager post-retour**: `${live.enrollmentReturnedWithBiometricCheck}`")
            line("- **Sources observées (${live.observedSources.size})**: ${live.observedSources.joinToString(", ") { "`$it`" }}")
            line("- **Tampon tronqué**: `${live.rawBufferTruncated}`")
            line()
            if (live.events.isEmpty()) {
                line("_Aucun événement capturé._")
            } else {
                live.events.forEach { evt ->
                    line("#### `+${evt.relativeMs}ms` `${evt.type.name}` (`${evt.id}`)")
                    line("- **Source**: `${evt.source}` | **Type**: `${evt.observationType.name}` | **Confiance**: `${evt.confidence.name}` | **Monotone**: `${evt.monotonicNanos}ns`")
                    line("- **Télémétrie**: `${evt.data}`")
                    evt.procStateNote?.let { line("- **État Processus (/proc)**: `$it`") }
                    if (evt.codeRefs.isNotEmpty()) {
                        line("- **Code / Binaire corrélé**:")
                        evt.codeRefs.forEach { ref ->
                            line("  - **`${ref.artifactPath}`** -> `${ref.symbolOrMethod}`" + (ref.targetResource?.let { " (cible: `$it`)" } ?: ""))
                            ref.callerChain.forEach { chain ->
                                line("    - Chaîne Xref: `$chain`")
                            }
                        }
                    }
                    line()
                }
            }
        }

        // 6. Deep Root Read-Only Telemetry
        line("## 6. Télémétrie Système Approfondie (/proc, binder_logs, tracefs, dumpsys)")
        line()
        if (live != null) {
            if (live.runtimeSnapshots.isNotEmpty()) {
                line("### Instantanés Processus (`/proc/<pid>`)")
                live.runtimeSnapshots.forEach { snap ->
                    line("#### `${snap.processName}` (PID `${snap.pid}`)")
                    snap.wchan?.let { line("- **wchan**: `$it`") }
                    snap.syscall?.let { line("- **syscall**: `$it`") }
                    if (snap.kernelStack.isNotEmpty()) {
                        line("- **Kernel Stack (`/proc/${snap.pid}/stack`)**:")
                        line("```")
                        snap.kernelStack.forEach { line(it) }
                        line("```")
                    }
                    if (snap.openFodDescriptors.isNotEmpty()) {
                        line("- **Descripteurs ouverts (`/proc/${snap.pid}/fd`)**:")
                        line("```")
                        snap.openFodDescriptors.forEach { line(it) }
                        line("```")
                    }
                    if (snap.loadedFodLibraries.isNotEmpty()) {
                        line("- **Bibliothèques & APKs mappés (`/proc/${snap.pid}/maps`)**:")
                        snap.loadedFodLibraries.forEach { line("  - `$it`") }
                    }
                    line()
                }
            }
            if (live.binderTransactions.isNotEmpty()) {
                line("### Transactions `binder_logs` observées (${live.binderTransactions.size})")
                line("```")
                live.binderTransactions.forEach { line(it) }
                line("```")
                line()
            }
            if (live.tracefsEvents.isNotEmpty()) {
                line("### Événements `tracefs` passifs observés (${live.tracefsEvents.size})")
                line("```")
                live.tracefsEvents.forEach { line(it) }
                line("```")
                line()
            }
            live.surfaceFlingerSnapshot?.let { sf ->
                line("### Snapshot `dumpsys SurfaceFlinger`")
                line("```")
                line(sf)
                line("```")
                line()
            }
            live.dumpsysFingerprintDelta?.let { fp ->
                line("### Delta `dumpsys fingerprint`")
                line("```")
                line(fp)
                line("```")
                line()
            }
            if (live.dumpsysDiffs.isNotEmpty()) {
                line("### Différentiels `dumpsys` (biometric/display/input/SurfaceFlinger)")
                line("```")
                live.dumpsysDiffs.forEach { line(it) }
                line("```")
                line()
            }
        } else {
            line("_Aucune capture live disponible._")
            line()
        }

        // 7. Evidence & Inaccessible
        line("## 7. Preuves Épistémiques & Ressources Inaccessibles")
        line()
        val inaccessibleLive = live?.inaccessibleSources.orEmpty()
        val inaccessibleEv = session.evidence.filter { it.epistemicLevel == EpistemicLevel.INACCESSIBLE }
        if (inaccessibleLive.isNotEmpty() || inaccessibleEv.isNotEmpty()) {
            line("### Sources `INACCESSIBLE` (jamais supposées inexistantes)")
            inaccessibleLive.forEach { line("- `[LIVE]` `$it`") }
            inaccessibleEv.forEach { line("- `[${it.id}]` `${it.source}`: ${it.observedValue}") }
            line()
        }
        val provedEv = session.evidence.filter { it.epistemicLevel == EpistemicLevel.PROVED }
        line("### Faits `PROVED` (${provedEv.size})")
        provedEv.forEach { ev ->
            line("- **`${ev.id}`** (`${ev.resourceType}`, `${ev.accessLevel.name}`, `${ev.source}`): `${ev.observedValue}`")
        }
        line()

        // 8. Anomalies, Correlations & Hypotheses
        line("## 8. Anomalies, Corrélations & Hypothèses")
        line()
        line("### Anomalies (${session.anomalies.size})")
        if (session.anomalies.isEmpty()) {
            line("_Aucune anomalie prouvée détectée._")
        } else {
            session.anomalies.forEach { a ->
                line("- **`${a.id}` [${a.severity.name} / ${a.epistemicLevel.name}] ${a.title}** (`${a.componentName}`)")
                line("  - Description: ${a.description}")
                if (a.possibleCauses.isNotEmpty()) line("  - Causes possibles: ${a.possibleCauses.joinToString("; ")}")
                if (a.recommendedSteps.isNotEmpty()) line("  - Vérifications suggérées: ${a.recommendedSteps.joinToString("; ")}")
            }
        }
        line()
        line("### Corrélations (${session.correlations.size})")
        session.correlations.forEach { c ->
            line("- **`${c.id}` [${c.epistemicLevel.name}] ${c.title}**")
            line("  - Attendu: ${c.expectedChain}")
            line("  - Observé: ${c.observedBehavior}")
            c.unverifiableReason?.let { line("  - Limite: $it") }
        }
        line()
        line("### Hypothèses (${session.hypotheses.size})")
        session.hypotheses.forEach { h ->
            line("- **`${h.id}` [${h.confidence.name}] ${h.statement}**")
            line("  - Raisonnement: ${h.rationale}")
            if (h.missingData.isNotEmpty()) line("  - Données manquantes: ${h.missingData.joinToString("; ")}")
            line("  - Test de vérification: ${h.verificationHint}")
        }
        line()

        // 9. GSI Solutions
        line("## 9. Solutions & Analyse de Faisabilité GSI")
        line()
        if (session.solutions.isEmpty()) {
            line("_Aucune proposition de solution générée._")
        } else {
            session.solutions.forEach { s ->
                line("### `${s.id}` [${s.category.name} | ${s.feasibility.name}] — ${s.problemIdentified}")
                line("- **Composant**: `${s.componentName}` (`${s.componentLocation}`, `${s.partitionOrigin.name}`)")
                line("- **Cause probable**: ${s.probableCause}")
                if (s.technicalPrerequisites.isNotEmpty()) line("- **Prérequis**: ${s.technicalPrerequisites.joinToString("; ")}")
                if (s.compatibilityRisks.isNotEmpty()) line("- **Risques**: ${s.compatibilityRisks.joinToString("; ")}")
                line("- **Méthode de validation**: ${s.validationMethod}")
                line()
            }
        }

        // 10. AI Analysis
        session.aiAnalysis?.let { ai ->
            line("## 10. Synthèse Assistée par IA")
            line("- **Modèle**: `${ai.modelName}` | **Thinking**: `${ai.thinkingLevel}`")
            line("- **Avertissement**: _${ai.disclaimer}_")
            line()
            line(ai.summary)
            if (ai.investigationLeads.isNotEmpty()) {
                line()
                line("**Pistes d'investigation :**")
                ai.investigationLeads.forEach { line("- $it") }
            }
            line()
        }

        // 11. Complete Disassembly Listings
        line("## 11. Désassemblage Complet & Listings Bruts")
        line()
        val emittedRawKeys = HashSet<String>()
        if (session.disassembledArtifacts.isEmpty() && session.rawArtifacts.isEmpty()) {
            line("_Aucun artefact désassemblé extrait pour cette session._")
        } else {
            session.disassembledArtifacts.forEach { art ->
                line("### `${art.id}` ${art.name} (`${art.kind.name}` • `${art.partition.name}`)")
                line("- **Chemin**: `${art.path}`")
                art.architecture?.let { line("- **Architecture**: `$it`") }
                line("- **Statut épistémique**: `${art.epistemicLevel.name}`")
                if (art.neededLibraries.isNotEmpty()) {
                    line("- **Dépendances / DEX (`DT_NEEDED`)**: ${art.neededLibraries.joinToString(", ") { "`$it`" }}")
                }
                if (art.decodedResources.isNotEmpty()) {
                    line("- **Ressources décodées (`AXML` / `resources.arsc`)**:")
                    art.decodedResources.forEach { line("  - `$it`") }
                }
                if (art.crossReferences.isNotEmpty()) {
                    line("- **Références croisées (Appels -> Cibles)**:")
                    art.crossReferences.forEach { line("  - `$it`") }
                }
                if (art.keySymbols.isNotEmpty()) {
                    line("- **Symboles / Classes clés (${art.keySymbols.size})**:")
                    art.keySymbols.forEach { line("  - `$it`") }
                }
                if (art.extractedStrings.isNotEmpty()) {
                    line("- **Chaînes / Descripteurs extraits (${art.extractedStrings.size})**:")
                    art.extractedStrings.forEach { line("  - `$it`") }
                }
                val rawBody = art.rawFileName?.let { key ->
                    emittedRawKeys += key
                    session.rawArtifacts[key] ?: diskRawResolver?.invoke(key)
                } ?: art.disassemblySnippet

                if (rawBody.isNotBlank()) {
                    line()
                    line("**Listing complet (`${art.rawFileName ?: art.path}`) :**")
                    line("```")
                    line(rawBody.trimEnd())
                    line("```")
                }
                line()
            }

            session.rawArtifacts.forEach { (key, body) ->
                if (key !in emittedRawKeys && body.isNotBlank()) {
                    line("### Artefact brut : `$key`")
                    line("```")
                    line(body.trimEnd())
                    line("```")
                    line()
                }
            }
        }
        writer.flush()
    }

    private fun escMd(raw: String): String =
        raw.replace("|", "\\|").replace("\n", " ").replace("\r", "")

    private fun formatUtc(ms: Long): String {
        val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        return sdf.format(Date(ms))
    }
}
