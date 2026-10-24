package com.forgelab.webhacktoolkit

import android.content.Context
import android.content.Intent

object ReportExporter {
    fun shareJson(context: Context, report: ScanReport) {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_SUBJECT, "WebHack Toolkit scan report")
            putExtra(Intent.EXTRA_TEXT, report.toJson())
        }
        context.startActivity(Intent.createChooser(intent, "Share scan report"))
    }
}
