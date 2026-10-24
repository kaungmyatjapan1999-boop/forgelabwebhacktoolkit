package com.forgelab.webhacktoolkit

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var urlInput: EditText
    private lateinit var scanButton: Button
    private lateinit var progress: ProgressBar
    private lateinit var resultView: TextView
    private var latestReport: ScanReport? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val scroll = ScrollView(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 28, 24, 24)
        }
        scroll.addView(root)
        setContentView(scroll)

        root.addView(TextView(this).apply {
            text = "WEBHACK TOOLKIT"
            textSize = 26f
            typeface = Typeface.DEFAULT_BOLD
        })
        root.addView(TextView(this).apply {
            text = "Website security checks • HTTPS only • Authorized targets only"
            textSize = 14f
            setPadding(0, 8, 0, 20)
        })

        urlInput = EditText(this).apply {
            hint = "https://example.com"
            singleLine = true
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_URI
        }
        root.addView(urlInput, matchWidth())

        scanButton = Button(this).apply { text = "START SECURITY SCAN" }
        root.addView(scanButton, matchWidth())
        progress = ProgressBar(this).apply { visibility = View.GONE }
        root.addView(progress)

        root.addView(Button(this).apply {
            text = "Share JSON report"
            setOnClickListener {
                val report = latestReport
                if (report == null) toast("Run a scan first.")
                else ReportExporter.shareJson(this@MainActivity, report)
            }
        }, matchWidth())

        root.addView(Button(this).apply {
            text = "Show scan history"
            setOnClickListener {
                val items = ScanHistory.getAll(this@MainActivity)
                resultView.text = if (items.isEmpty()) "No saved scans yet."
                    else "RECENT SCAN REPORTS\n\n" + items.joinToString("\n\n--------------------\n\n")
            }
        }, matchWidth())

        root.addView(Button(this).apply {
            text = "Clear scan history"
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("Clear history?")
                    .setMessage("This deletes locally stored scan reports.")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Clear") { _, _ ->
                        ScanHistory.clear(this@MainActivity)
                        toast("Scan history cleared.")
                    }.show()
            }
        }, matchWidth())

        resultView = TextView(this).apply {
            textSize = 14f
            textIsSelectable = true
            setPadding(0, 20, 0, 0)
        }
        root.addView(resultView)

        scanButton.setOnClickListener {
            val target = urlInput.text.toString().trim()
            if (target.isBlank()) {
                urlInput.error = "Enter a website."
                return@setOnClickListener
            }
            scanButton.isEnabled = false
            progress.visibility = View.VISIBLE
            resultView.text = "Scanning…"
            executor.execute {
                val report = try {
                    SecurityScanner.scan(target)
                } catch (e: Exception) {
                    ScanReport(
                        target = target,
                        scannedAt = java.time.Instant.now().toString(),
                        finalUrl = target,
                        httpStatus = null,
                        tlsSummary = "Not available",
                        dnsAddresses = emptyList(),
                        responseHeaders = emptyMap(),
                        findings = listOf(e.message ?: "Scan failed."),
                        technologyHints = emptyList(),
                        redirects = emptyList(),
                        error = e.message ?: "Scan failed."
                    )
                }
                runOnUiThread {
                    latestReport = report
                    ScanHistory.add(this@MainActivity, report)
                    resultView.text = render(report)
                    scanButton.isEnabled = true
                    progress.visibility = View.GONE
                }
            }
        }
    }

    private fun matchWidth() = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
    )

    private fun render(report: ScanReport): String = buildString {
        appendLine("SCAN REPORT")
        appendLine("Target: ${report.target}")
        appendLine("Scanned at: ${report.scannedAt}")
        appendLine("Final URL: ${report.finalUrl}")
        appendLine("HTTP status: ${report.httpStatus ?: "Unknown"}")
        appendLine()
        appendLine("TLS / CERTIFICATE")
        appendLine(report.tlsSummary)
        appendLine()
        appendLine("DNS ADDRESSES")
        report.dnsAddresses.forEach { appendLine("• $it") }
        appendLine()
        appendLine("SECURITY FINDINGS")
        report.findings.forEach { appendLine("• $it") }
        appendLine()
        appendLine("TECHNOLOGY HINTS")
        if (report.technologyHints.isEmpty()) appendLine("• No common server hints found.")
        report.technologyHints.forEach { appendLine("• $it") }
        appendLine()
        appendLine("REDIRECTS")
        if (report.redirects.isEmpty()) appendLine("• No redirects recorded.")
        report.redirects.forEach { appendLine("• $it") }
        appendLine()
        appendLine("RESPONSE HEADERS")
        report.responseHeaders.forEach { (key, value) -> appendLine("$key: $value") }
        report.error?.let { appendLine("\nNOTE: $it") }
        appendLine("\nLimited baseline checks only; results are not a full penetration test.")
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}
