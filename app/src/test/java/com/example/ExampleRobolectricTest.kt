package com.example

import android.content.Context
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.example.fodtracer.app.i18n.FrenchFodStrings
import com.example.fodtracer.app.i18n.LocalFodStrings
import com.example.fodtracer.app.screens.HomeScreen
import com.example.fodtracer.core.comparator.ReferenceBaselineFixtures
import com.example.fodtracer.data.archives.ArchiveManager
import com.example.fodtracer.domain.interfaces.PrivilegeSnapshot
import com.example.fodtracer.domain.models.RootState
import com.example.fodtracer.domain.models.SeLinuxMode
import com.example.fodtracer.domain.models.ThemePreference
import com.example.ui.theme.FodTracerTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun `app name matches FodTracer`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appName = context.getString(R.string.app_name)
        assertEquals("FodTracer", appName)
    }

    @Test
    fun `ArchiveManager exports and verifies SHA256 ZIP archive round-trip`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val manager = ArchiveManager(context)
        val session = ReferenceBaselineFixtures.createWorkingCustomRomBaseline()

        val fileMap = manager.buildStructuredFileMap(session)
        val zipBytes = manager.createZipBytes(fileMap)
        val restored = manager.parseAndVerifyZipStream(ByteArrayInputStream(zipBytes))

        assertEquals(session.sessionId, restored.sessionId)
        assertEquals(session.environment.model, restored.environment.model)
        assertEquals(session.components.size, restored.components.size)
    }

    @Test
    fun `ArchiveManager rejects Zip-Slip traversal and tampered SHA256 archives`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val manager = ArchiveManager(context)

        // 1. Zip-Slip traversal
        val slipBytes = ByteArrayOutputStream().use { baos ->
            ZipOutputStream(baos).use { zos ->
                zos.putNextEntry(ZipEntry("../../etc/evil.txt"))
                zos.write("bad".toByteArray())
                zos.closeEntry()
            }
            baos.toByteArray()
        }
        val slipErr = runCatching {
            manager.parseAndVerifyZipStream(ByteArrayInputStream(slipBytes))
        }.exceptionOrNull()
        assertTrue(slipErr is SecurityException)

        // 2. Tampered file failing SHA-256 verification
        val session = ReferenceBaselineFixtures.createWorkingCustomRomBaseline()
        val fileMap = manager.buildStructuredFileMap(session).toMutableMap()
        fileMap["environment.json"] = fileMap["environment.json"]!! + "\n// tampered"
        val tamperedBytes = manager.createZipBytes(fileMap)
        val hashErr = runCatching {
            manager.parseAndVerifyZipStream(ByteArrayInputStream(tamperedBytes))
        }.exceptionOrNull()
        assertTrue(hashErr is SecurityException)
        // 3. Incompatible schemaVersion
        val badSchemaMap = manager.buildStructuredFileMap(session).toMutableMap()
        badSchemaMap["manifest.json"] = badSchemaMap["manifest.json"]!!.replace("\"schemaVersion\": 1", "\"schemaVersion\": 99")
        val badSchemaBytes = manager.createZipBytes(badSchemaMap)
        val schemaErr = runCatching {
            manager.parseAndVerifyZipStream(ByteArrayInputStream(badSchemaBytes))
        }.exceptionOrNull()
        assertTrue(schemaErr is SecurityException)

        // 4. Duplicate ZIP entry (write distinct 13-char name then patch bytes to create genuine duplicate entry in stream)
        val rawDupBytes = ByteArrayOutputStream().use { baos ->
            ZipOutputStream(baos).use { zos ->
                zos.putNextEntry(ZipEntry("manifest.json"))
                zos.write("{}".toByteArray())
                zos.closeEntry()
                zos.putNextEntry(ZipEntry("manif2st.json"))
                zos.write("{}".toByteArray())
                zos.closeEntry()
            }
            baos.toByteArray()
        }
        val dupStr = String(rawDupBytes, Charsets.ISO_8859_1).replace("manif2st.json", "manifest.json")
        val dupBytes = dupStr.toByteArray(Charsets.ISO_8859_1)
        val dupErr = runCatching {
            manager.parseAndVerifyZipStream(ByteArrayInputStream(dupBytes))
        }.exceptionOrNull()
        assertTrue(dupErr is SecurityException)
    }

    @Test
    fun `HomeScreen renders minimalist feature strip and expands Comparator card`() {
        var openedDiagnostic = false
        var openedComparator = false
        val priv = PrivilegeSnapshot(
            suBinaryFound = false,
            suBinaryPath = null,
            rootState = RootState.NOT_AVAILABLE,
            rootProviderHint = null,
            rootUidInfo = null,
            seLinuxMode = SeLinuxMode.ENFORCING,
            seLinuxContext = null,
            manageExternalStorageGranted = false,
            postNotificationsGranted = false,
            publicFodDirPath = "/sdcard/FODtracer",
            publicFodDirWritable = false
        )

        composeRule.setContent {
            CompositionLocalProvider(LocalFodStrings provides FrenchFodStrings) {
                FodTracerTheme(themePreference = ThemePreference.LIGHT) {
                    HomeScreen(
                        privilegeSnapshot = priv,
                        activeSession = null,
                        sessionCount = 0,
                        comparisonCount = 0,
                        onOpenDiagnostic = { openedDiagnostic = true },
                        onOpenComparator = { openedComparator = true },
                        onOpenSolutions = {},
                        onOpenArchives = {},
                        onOpenSettings = {}
                    )
                }
            }
        }

        composeRule.onNodeWithText("FodTracer").assertIsDisplayed()
        composeRule.onNodeWithTag("open_feature_diagnostic").assertIsDisplayed().performClick()
        assertTrue(openedDiagnostic)

        composeRule.onNodeWithTag("feature_card_comparator").performClick()
        composeRule.onNodeWithTag("open_feature_comparator").assertIsDisplayed().performClick()
        assertTrue(openedComparator)
    }
}
