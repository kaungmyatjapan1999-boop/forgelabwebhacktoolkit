package com.forgelab.webhacktoolkit

import android.content.Context
import org.json.JSONArray

object ScanHistory {
    private const val PREFS_NAME = "webhack_scan_history"
    private const val KEY_REPORTS = "reports"
    private const val MAX_ITEMS = 20

    @Synchronized
    fun add(context: Context, report: ScanReport) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val old = JSONArray(prefs.getString(KEY_REPORTS, "[]"))
        val next = JSONArray()
        next.put(report.toJson())
        for (i in 0 until minOf(old.length(), MAX_ITEMS - 1)) {
            next.put(old.get(i))
        }
        prefs.edit().putString(KEY_REPORTS, next.toString()).apply()
    }

    fun getAll(context: Context): List<String> {
        return try {
            val raw = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_REPORTS, "[]")
            val arr = JSONArray(raw)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().remove(KEY_REPORTS).apply()
    }
}
