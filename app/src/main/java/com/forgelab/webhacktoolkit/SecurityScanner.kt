package com.forgelab.webhacktoolkit

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.net.URL
import java.time.Instant
import java.util.Locale
import javax.net.ssl.HttpsURLConnection

object SecurityScanner {
    private const val CONNECT_TIMEOUT_MS = 8000
    private const val READ_TIMEOUT_MS = 8000
    private const val MAX_REDIRECTS = 5

    fun scan(input: String): ScanReport {
        val original = normalize(input)
        val parsed = URI(original)
        val initialHost = parsed.host ?: error("Invalid hostname")
        val dns = InetAddress.getAllByName(initialHost)
        require(dns.isNotEmpty()) { "DNS lookup returned no addresses." }
        require(dns.all { isPublicAddress(it) }) {
            "Private, local, or reserved IP destinations are blocked."
        }

        var current = original
        val redirects = mutableListOf<String>()
        var httpStatus: Int? = null
        var finalHeaders = emptyMap<String, String>()
        var tlsSummary = "Not available"
        var errorMessage: String? = null
        var hop = 0

        try {
            while (true) {
                val uri = URI(current)
                require(uri.scheme.equals("https", true)) { "Redirect to non-HTTPS URL blocked." }
                val host = uri.host ?: error("Invalid redirect hostname")
                val addresses = InetAddress.getAllByName(host)
                require(addresses.isNotEmpty() && addresses.all { isPublicAddress(it) }) {
                    "Private, local, or reserved redirect destination blocked."
                }

                val connection = (URL(current).openConnection() as HttpsURLConnection).apply {
                    instanceFollowRedirects = false
                    connectTimeout = CONNECT_TIMEOUT_MS
                    readTimeout = READ_TIMEOUT_MS
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", "WebHackToolkit/1.0")
                    setRequestProperty("Accept", "*/*")
                }

                try {
                    httpStatus = connection.responseCode
                    val cert = try {
                        connection.serverCertificates.firstOrNull() as? java.security.cert.X509Certificate
                    } catch (_: Exception) { null }

                    tlsSummary = if (cert != null) {
                        "HTTPS/TLS handshake succeeded. Subject: ${cert.subjectX500Principal.name}; " +
                            "Issuer: ${cert.issuerX500Principal.name}; Expires: ${cert.notAfter}"
                    } else {
                        "HTTPS/TLS connection succeeded; certificate details unavailable."
                    }

                    finalHeaders = connection.headerFields
                        .filterKeys { it != null }
                        .mapKeys { it.key ?: "" }
                        .mapValues { it.value?.joinToString("; ") ?: "" }

                    val location = connection.getHeaderField("Location")
                    if (httpStatus in 300..399 && !location.isNullOrBlank()) {
                        if (hop >= MAX_REDIRECTS) {
                            errorMessage = "Redirect limit reached ($MAX_REDIRECTS)."
                            break
                        }
                        val next = URI(current).resolve(location).toString()
                        require(URI(next).scheme.equals("https", true)) {
                            "Redirect to non-HTTPS URL blocked."
                        }
                        redirects.add("HTTP $httpStatus: $current -> $next")
                        current = next
                        hop++
                        continue
                    }

                    try {
                        val stream = if ((httpStatus ?: 0) >= 400) connection.errorStream
                                     else connection.inputStream
                        stream?.use { inputStream ->
                            val buffer = ByteArray(4096)
                            var total = 0
                            while (total < 16384) {
                                val count = inputStream.read(buffer, 0, minOf(buffer.size, 16384 - total))
                                if (count <= 0) break
                                total += count
                            }
                        }
                    } catch (_: Exception) { }
                    break
                } finally {
                    connection.disconnect()
                }
            }
        } catch (e: Exception) {
            errorMessage = e.message ?: e.javaClass.simpleName
        }

        val lowerHeaders = finalHeaders.entries.associate {
            it.key.lowercase(Locale.US) to it.value
        }
        val findings = mutableListOf<String>()
        val checks = listOf(
            "strict-transport-security" to "HSTS",
            "content-security-policy" to "Content-Security-Policy",
            "x-content-type-options" to "X-Content-Type-Options",
            "referrer-policy" to "Referrer-Policy",
            "permissions-policy" to "Permissions-Policy"
        )
        checks.forEach { (key, label) ->
            if (lowerHeaders[key].isNullOrBlank()) {
                findings.add("Missing $label response header.")
            } else {
                findings.add("$label header is present.")
            }
        }

        finalHeaders.filterKeys { it.equals("Set-Cookie", true) }.values.forEach { cookie ->
            val lower = cookie.lowercase(Locale.US)
            if (!lower.contains("secure")) findings.add("A Set-Cookie response may be missing Secure.")
            if (!lower.contains("httponly")) findings.add("A Set-Cookie response may be missing HttpOnly.")
            if (!lower.contains("samesite")) findings.add("A Set-Cookie response may be missing SameSite.")
        }

        val tech = mutableListOf<String>()
        finalHeaders.entries.firstOrNull { it.key.equals("Server", true) }?.let {
            tech.add("Server: ${it.value}")
        }
        finalHeaders.entries.firstOrNull { it.key.equals("X-Powered-By", true) }?.let {
            tech.add("X-Powered-By: ${it.value}")
        }
        if (findings.isEmpty()) findings.add("No findings were produced by the limited checks.")

        return ScanReport(
            target = original,
            scannedAt = Instant.now().toString(),
            finalUrl = current,
            httpStatus = httpStatus,
            tlsSummary = tlsSummary,
            dnsAddresses = dns.map { it.hostAddress ?: it.hostName },
            responseHeaders = finalHeaders,
            findings = findings,
            technologyHints = tech,
            redirects = redirects,
            error = errorMessage
        )
    }

    private fun normalize(raw: String): String {
        val value = raw.trim()
        require(value.isNotEmpty()) { "Enter a website URL." }
        require(value.length <= 2048) { "URL is too long." }
        val full = if (value.contains("://")) value else "https://$value"
        val uri = URI(full)
        require(uri.scheme.equals("https", true)) { "Only HTTPS URLs are supported." }
        require(uri.host != null) { "Enter a valid hostname." }
        require(uri.userInfo == null) { "Credentials inside URLs are not allowed." }
        require(uri.port == -1 || uri.port == 443) { "Only HTTPS port 443 is supported." }
        return uri.toString()
    }

    private fun isPublicAddress(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress ||
            address.isLinkLocalAddress || address.isSiteLocalAddress ||
            address.isMulticastAddress) return false

        if (address is Inet4Address) {
            val b = address.address.map { it.toInt() and 0xff }
            if (b[0] == 0 || b[0] == 10 || b[0] == 127 ||
                (b[0] == 169 && b[1] == 254) ||
                (b[0] == 172 && b[1] in 16..31) ||
                (b[0] == 192 && b[1] == 168) ||
                (b[0] == 100 && b[1] in 64..127) ||
                (b[0] == 198 && b[1] in 18..19) || b[0] >= 224) return false
        }
        if (address is Inet6Address) {
            val first = address.address[0].toInt() and 0xff
            if ((first and 0xfe) == 0xfc) return false
        }
        return true
    }
}
