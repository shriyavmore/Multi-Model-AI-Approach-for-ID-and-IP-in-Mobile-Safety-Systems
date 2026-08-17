package com.mobilesecurity.idps.api

import com.mobilesecurity.idps.model.AppRecord
import com.mobilesecurity.idps.model.ScanResultResponse
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

interface ApiService {

    @POST("api/scan")
    suspend fun scanApp(@Body appRecord: AppRecord): Response<ScanResultResponse>

    @GET("api/apps")
    suspend fun getInstalledApps(): Response<List<AppRecord>>

    @GET("api/reports/{scan_id}")
    suspend fun getSecurityReport(@Path("scan_id") scanId: Int): Response<Map<String, Any>>

    @GET("api/monitoring/status")
    suspend fun getMonitoringStatus(): Response<Map<String, Any>>
}
