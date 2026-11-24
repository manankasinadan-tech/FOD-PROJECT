package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.example.fodtracer.app.navigation.FodTracerApp
import com.example.fodtracer.core.ai.configureAppCheck
import com.example.fodtracer.presentation.AppContainer

class MainActivity : ComponentActivity() {

    private lateinit var appContainer: AppContainer

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // App Check MUST be configured before any Firebase AI Logic instance or ViewModel runs.
        configureAppCheck(this, intent)
        enableEdgeToEdge()

        appContainer = AppContainer(applicationContext)

        setContent {
            FodTracerApp(container = appContainer)
        }
    }
}
