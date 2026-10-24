package com.forgelab.webhacktoolkit

import org.json.JSONArray
import org.json.JSONObject

data class ScanReport(
    val target: String,
    val scannedAt: String,
    val finalUrl: String,
    val httpStatus: Int?,
    val tlsSummary: String,
    val dnsAddresses: List<String>,
    val responseHeaders: Map<String, String>,
    val findings: List<String>,
    val technologyHints: List<String>,
    val redirects: List<String>,
    val error: String? = null
) {
    fun toJson(): String {
        val obj = JSONObject()
        obj.put("target", target)
        obj.put("scannedAt", scannedAt)
        obj.put("finalUrl", finalUrl)
        obj.put("httpStatus", httpStatus ?: JSONObject.NULL)
        obj.put("tlsSummary", tlsSummary)
        obj.put("dnsAddresses", JSONArray(dnsAddresses))
        val headers = JSONObject()
        responseHeaders.forEach { (key, value) -> headers.put(key, value) }
        obj.put("responseHeaders", headers)
        obj.put("findings", JSONArray(findings))
        obj.put("technologyHints", JSONArray(technologyHints))
        obj.put("redirects", JSONArray(redirects))
        obj.put("error", error ?: JSONObject.NULL)
        return obj.toString(2)
    }
}
