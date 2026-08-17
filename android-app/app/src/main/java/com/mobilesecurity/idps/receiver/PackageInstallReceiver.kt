package com.mobilesecurity.idps.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.mobilesecurity.idps.api.ApiClient
import com.mobilesecurity.idps.service.AppScannerService
import com.mobilesecurity.idps.util.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch


class PackageInstallReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "PackageInstallReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        // Diagnostic log at VERY FIRST LINE of onReceive as required
        Log.d(TAG, "onReceive triggered: action=${intent.action}, data=${intent.data}")

        val action = intent.action
        if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REPLACED) {
            val packageName = intent.data?.schemeSpecificPart ?: return
            
            // Avoid scanning self-installation loop
            if (packageName == context.packageName) return

            val isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            Log.d(TAG, "New or updated application installation detected: $packageName (action: $action, replacing: $isReplacing)")

            val pendingResult: PendingResult = goAsync()

            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val pm = context.packageManager
                    val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        PackageManager.GET_PERMISSIONS
                    } else {
                        @Suppress("DEPRECATION")
                        PackageManager.GET_PERMISSIONS
                    }

                    val pkgInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
                    } else {
                        @Suppress("DEPRECATION")
                        pm.getPackageInfo(packageName, flags)
                    }

                    val scannerService = AppScannerService(context)
                    val appRecord = scannerService.extractAppRecord(pm, pkgInfo)

                    Log.d(TAG, "Automatically dispatching app features for IDPS analysis: $packageName")
                    val response = ApiClient.apiService.scanApp(appRecord)

                    if (response.isSuccessful) {
                        val result = response.body()
                        result?.let {
                            val verdict = it.aiMlEnsemble.finalClassification
                            val score = it.aiMlEnsemble.finalRiskScore
                            val severity = it.threatDecision.severity
                            Log.i(TAG, "IDPS Automatic Scan Complete [$packageName] -> Verdict: $verdict | Score: $score/100 | Severity: $severity")

                            NotificationHelper.sendSecurityNotification(
                                context,
                                "⚠ New Application Detected",
                                "Application: ${appRecord.appName}\nRisk Score: $score/100 ($severity Threat Level)\nVerdict: $verdict"
                            )
                        }
                    } else {
                        Log.e(TAG, "IDPS Scan API server returned HTTP error code: ${response.code()}")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed automatic IDPS scan for package $packageName: ${e.message}", e)
                } finally {
                    pendingResult.finish()
                }
            }
        }
    }
}
