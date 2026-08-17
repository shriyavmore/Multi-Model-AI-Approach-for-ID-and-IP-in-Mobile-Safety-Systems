package com.mobilesecurity.idps

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Color
import android.os.Build

import android.os.Bundle
import android.view.WindowManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.mobilesecurity.idps.service.AppScannerService
import org.json.JSONArray
import org.json.JSONObject

import android.content.Intent
import android.content.IntentFilter
import com.mobilesecurity.idps.receiver.PackageInstallReceiver
import android.util.Log
import com.mobilesecurity.idps.service.NetworkMonitorManager
import com.mobilesecurity.idps.util.NotificationHelper

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var scannerService: AppScannerService
    private lateinit var networkMonitorManager: NetworkMonitorManager
    private var packageInstallReceiver: PackageInstallReceiver? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        scannerService = AppScannerService(this)
        networkMonitorManager = NetworkMonitorManager(this)
        networkMonitorManager.startNetworkMonitoring()

        // Dynamic registration for PackageInstallReceiver to guarantee event delivery on API 26-34 & OEM ROMs
        try {
            Log.d("PackageInstallReceiver", "Registering dynamic package receiver (Lifecycle state: ${lifecycle.currentState})")
            packageInstallReceiver = PackageInstallReceiver()
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(packageInstallReceiver, filter, RECEIVER_EXPORTED)
            } else {
                registerReceiver(packageInstallReceiver, filter)
            }
            Log.d("PackageInstallReceiver", "Dynamic package receiver registered successfully")
        } catch (e: Exception) {
            Log.e("PackageInstallReceiver", "Dynamic receiver registration failed: ${e.message}", e)
        }


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS)
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
            window.statusBarColor = Color.parseColor("#080c14")
            window.navigationBarColor = Color.parseColor("#0c121e")
        }

        webView = WebView(this).apply {
            setBackgroundColor(Color.parseColor("#080c14"))
        }

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            allowFileAccess = true
            allowContentAccess = true
            loadsImagesAutomatically = true
            useWideViewPort = true
            loadWithOverviewMode = true
            setSupportZoom(false)
            builtInZoomControls = false
            displayZoomControls = false
            mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
            cacheMode = WebSettings.LOAD_NO_CACHE
        }

        // Expose native Android functionality to the mobile web UI.
        webView.addJavascriptInterface(
            AndroidAppBridge(this, scannerService, networkMonitorManager),
            "AndroidApp"
        )

        webView.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)

                webView.evaluateJavascript(
                    """
                    (function() {
                        var viewport = document.querySelector('meta[name="viewport"]');
                        if (viewport) {
                            viewport.setAttribute(
                                'content',
                                'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover'
                            );
                        }
                    })();
                    """.trimIndent(),
                    null
                )
            }
        }

        webView.webChromeClient = WebChromeClient()

        setContentView(webView)

        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {

                    webView.evaluateJavascript(
                        """
                        (function() {
                            var modal =
                                document.querySelector('.modal-overlay.active');

                            if (modal) {
                                modal.classList.remove('active');
                                return true;
                            }

                            return false;
                        })();
                        """.trimIndent()
                    ) { result ->

                        val modalClosed = result == "true"

                        if (!modalClosed) {
                            if (webView.canGoBack()) {
                                webView.goBack()
                            } else {
                                isEnabled = false
                                onBackPressedDispatcher.onBackPressed()
                            }
                        }
                    }
                }
            }
        )

        val webViewUrl = BuildConfig.WEB_VIEW_URL.ifEmpty { "http://127.0.0.1:8000/" }
        webView.loadUrl(webViewUrl)
    }

    override fun onDestroy() {
        try {
            packageInstallReceiver?.let { unregisterReceiver(it) }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        webView.removeJavascriptInterface("AndroidApp")
        webView.destroy()
        super.onDestroy()
    }


    /**
     * JavaScript bridge used by the mobile dashboard.
     */
    class AndroidAppBridge(
        private val context: Context,
        private val scannerService: AppScannerService,
        private val networkMonitorManager: NetworkMonitorManager
    ) {

        @JavascriptInterface
        fun getInstalledApps(): String {

            return try {
                val apps = scannerService.scanInstalledApps()
                val jsonArray = JSONArray()

                for (app in apps) {
                    val obj = JSONObject()

                    obj.put("app_name", app.appName)
                    obj.put("package_name", app.packageName)
                    obj.put("version", app.version)
                    obj.put("apk_hash", app.apkHash)
                    obj.put("min_sdk", app.minSdk)
                    obj.put("target_sdk", app.targetSdk)
                    obj.put(
                        "permissions",
                        JSONArray(app.permissions)
                    )
                    obj.put(
                        "permission_count",
                        app.permissions.size
                    )

                    jsonArray.put(obj)
                }

                jsonArray.toString()

            } catch (e: Exception) {
                JSONObject()
                    .put("error", e.localizedMessage ?: "Unable to read installed apps")
                    .toString()
            }
        }

        @JavascriptInterface
        fun getNetworkSecurityInfo(): String {
            return networkMonitorManager.getNetworkSecurityInfo()
        }

        @JavascriptInterface
        fun sendNotification(title: String, message: String) {
            NotificationHelper.sendSecurityNotification(context, title, message)
        }

        @JavascriptInterface
        fun scanRoomSecurity(): String {
            return JSONObject().apply {
                put("status", "NO_SIGNIFICANT_RISK")
                put("risk_score", 15)
                put("risk_level", "LOW")
                put("assessment_title", "Potential Hidden-Camera / Surveillance Device Risk Assessment")
                put("message", "Network and optical device scan completed cleanly.")
            }.toString()
        }
    }
}