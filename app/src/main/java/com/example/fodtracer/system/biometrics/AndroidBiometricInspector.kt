package com.example.fodtracer.system.biometrics

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import android.provider.Settings

data class BiometricApiSnapshot(
    val hasFingerprintFeature: Boolean,
    val hasBiometricFeature: Boolean,
    val statusCodeLabel: String,
    val isEnrolledOrReady: Boolean
)

class AndroidBiometricInspector(
    private val context: Context
) {
    fun inspectBiometricState(): BiometricApiSnapshot {
        val pm = context.packageManager
        val hasFp = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        val hasBio = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        } else {
            hasFp
        }

        if (!hasFp) {
            return BiometricApiSnapshot(
                hasFingerprintFeature = false,
                hasBiometricFeature = false,
                statusCodeLabel = "FEATURE_FINGERPRINT absent in PackageManager",
                isEnrolledOrReady = false
            )
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val bm = context.getSystemService(BiometricManager::class.java)
            val result = bm?.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                ?: BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE
            return when (result) {
                BiometricManager.BIOMETRIC_SUCCESS -> BiometricApiSnapshot(
                    true, true, "BIOMETRIC_SUCCESS (Strong biometric ready & enrolled)", true
                )
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricApiSnapshot(
                    true, true, "BIOMETRIC_ERROR_NONE_ENROLLED (Hardware ready, no fingers enrolled)", false
                )
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricApiSnapshot(
                    true, false, "BIOMETRIC_ERROR_NO_HARDWARE", false
                )
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricApiSnapshot(
                    true, true, "BIOMETRIC_ERROR_HW_UNAVAILABLE", false
                )
                BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricApiSnapshot(
                    true, true, "BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED", false
                )
                else -> BiometricApiSnapshot(true, true, "BIOMETRIC_STATUS_CODE_$result", false)
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            @Suppress("DEPRECATION")
            val bm = context.getSystemService(BiometricManager::class.java)
            @Suppress("DEPRECATION")
            val result = bm?.canAuthenticate() ?: BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE
            return BiometricApiSnapshot(
                hasFingerprintFeature = true,
                hasBiometricFeature = true,
                statusCodeLabel = "BiometricManager(API 29)=$result",
                isEnrolledOrReady = result == BiometricManager.BIOMETRIC_SUCCESS
            )
        }

        @Suppress("DEPRECATION")
        val fm = context.getSystemService(android.hardware.fingerprint.FingerprintManager::class.java)
        @Suppress("DEPRECATION")
        val hw = runCatching { fm?.isHardwareDetected == true }.getOrDefault(false)
        @Suppress("DEPRECATION")
        val enrolled = runCatching { fm?.hasEnrolledFingerprints() == true }.getOrDefault(false)
        return BiometricApiSnapshot(
            hasFingerprintFeature = true,
            hasBiometricFeature = hw,
            statusCodeLabel = "FingerprintManager hw=$hw enrolled=$enrolled",
            isEnrolledOrReady = enrolled
        )
    }

    /**
     * Builds the most appropriate system enrollment Intent for the running Android API level,
     * with deterministic fallback candidates for OEM/GSI compatibility.
     */
    fun resolveEnrollmentIntents(): List<Intent> {
        val pm = context.packageManager
        val candidates = mutableListOf<Intent>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            candidates += Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                putExtra(
                    Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                    BiometricManager.Authenticators.BIOMETRIC_STRONG
                )
            }
        }
        @Suppress("DEPRECATION")
        candidates += Intent(Settings.ACTION_FINGERPRINT_ENROLL)
        candidates += Intent(Settings.ACTION_SECURITY_SETTINGS)
        candidates += Intent(Settings.ACTION_SETTINGS)

        return candidates.filter { intent ->
            runCatching { pm.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY) != null }
                .getOrDefault(false)
        }
    }
}
