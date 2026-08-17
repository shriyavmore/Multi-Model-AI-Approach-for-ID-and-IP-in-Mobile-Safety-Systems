package com.mobilesecurity.idps.model

import com.google.gson.annotations.SerializedName

data class AppRecord(
    @SerializedName("package_name") val packageName: String,
    @SerializedName("app_name") val appName: String,
    @SerializedName("version") val version: String = "1.0.0",
    @SerializedName("apk_hash") val apkHash: String = "",
    @SerializedName("min_sdk") val minSdk: Int = 21,
    @SerializedName("target_sdk") val targetSdk: Int = 33,
    @SerializedName("permissions") val permissions: List<String> = emptyList(),
    @SerializedName("features") val features: List<String> = emptyList(),
    @SerializedName("network_connections_count") val networkConnectionsCount: Int = 0,
    @SerializedName("data_exfil_volume_kb") val dataExfilVolumeKb: Float = 0.0f,
    @SerializedName("background_exec_frequency") val backgroundExecFrequency: Float = 0.0f,
    @SerializedName("suspicious_api_calls_count") val suspiciousApiCallsCount: Int = 0
)

data class ScanResultResponse(
    @SerializedName("scan_id") val scanId: Int,
    @SerializedName("package_name") val packageName: String,
    @SerializedName("app_name") val appName: String,
    @SerializedName("scan_time") val scanTime: String,
    @SerializedName("ai_ml_ensemble") val aiMlEnsemble: EnsembleResult,
    @SerializedName("threat_decision") val threatDecision: ThreatDecision,
    @SerializedName("prevention_plan") val preventionPlan: PreventionPlan
)

data class EnsembleResult(
    @SerializedName("final_classification") val finalClassification: String,
    @SerializedName("final_risk_score") val finalRiskScore: Int,
    @SerializedName("confidence") val confidence: Float,
    @SerializedName("model_agreement") val modelAgreement: String,
    @SerializedName("xai_reasons") val xaiReasons: List<String>
)

data class ThreatDecision(
    @SerializedName("severity") val severity: String,
    @SerializedName("threat_type") val threatType: String,
    @SerializedName("description") val description: String
)

data class PreventionPlan(
    @SerializedName("prevention_status") val preventionStatus: String,
    @SerializedName("android_security_model_note") val securityNote: String
)
