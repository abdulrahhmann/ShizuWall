package com.arslan.shizuwall.incoming

import org.json.JSONObject

enum class IncomingVerdict {
    ALLOW,
    DENY;

    companion object {
        fun fromName(name: String?): IncomingVerdict? =
            entries.firstOrNull { it.name.equals(name, ignoreCase = true) }
    }
}

enum class IncomingProtocol(
    val displayName: String,
    val defaultPort: Int? = null,
    val isDiscovery: Boolean = false
) {
    ANY("Any"),
    TCP("TCP"),
    UDP("UDP"),
    ICMP("ICMP", isDiscovery = true),
    MDNS("mDNS", defaultPort = 5353, isDiscovery = true),
    SSDP("SSDP", defaultPort = 1900, isDiscovery = true),
    NETBIOS("NetBIOS", defaultPort = 137, isDiscovery = true),
    WSD("WS-Discovery", defaultPort = 3702, isDiscovery = true);

    fun iptablesProtocol(ipv6: Boolean): String? = when (this) {
        ANY -> null
        TCP -> "tcp"
        UDP, MDNS, SSDP, NETBIOS, WSD -> "udp"
        ICMP -> if (ipv6) "icmpv6" else "icmp"
    }

    fun supportsPort(): Boolean = when (this) {
        TCP, UDP, MDNS, SSDP, NETBIOS, WSD -> true
        ANY, ICMP -> false
    }

    fun matches(eventProtocol: IncomingProtocol): Boolean = when (this) {
        ANY -> true
        UDP -> eventProtocol == UDP || eventProtocol == MDNS || eventProtocol == SSDP ||
            eventProtocol == NETBIOS || eventProtocol == WSD
        else -> this == eventProtocol
    }

    companion object {
        fun fromName(name: String?): IncomingProtocol =
            entries.firstOrNull { it.name.equals(name, ignoreCase = true) } ?: ANY

        fun classifyUdpPort(dstPort: Int?): IncomingProtocol = when (dstPort) {
            5353 -> MDNS
            1900 -> SSDP
            137, 138 -> NETBIOS
            3702 -> WSD
            else -> UDP
        }
    }
}

object IpValidation {
    private val IPV4_REGEX = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")
    private val HEX_GROUP_REGEX = Regex("^[0-9a-fA-F]{1,4}$")

    fun normalizeIp(raw: String): String {
        val trimmed = raw.trim()
        val zoneIdx = trimmed.indexOf('%')
        val withoutZone = if (zoneIdx >= 0) trimmed.substring(0, zoneIdx) else trimmed
        return withoutZone.lowercase()
    }

    fun isValidIpv4(ip: String): Boolean {
        val match = IPV4_REGEX.matchEntire(ip) ?: return false
        return (1..4).all { i ->
            val part = match.groupValues[i]
            if (part.length > 1 && part.startsWith('0')) return false
            val num = part.toIntOrNull() ?: return false
            num in 0..255
        }
    }

    fun isValidIpv6(ip: String): Boolean {
        if (ip.isEmpty() || ip.length > 45 || !ip.contains(':')) return false
        if (ip.contains(":::")) return false
        for (ch in ip) {
            val ok = (ch in '0'..'9') || (ch in 'a'..'f') || (ch in 'A'..'F') || ch == ':' || ch == '.'
            if (!ok) return false
        }

        val doubleColonParts = ip.split("::")
        if (doubleColonParts.size > 2) return false
        val hasCompression = doubleColonParts.size == 2

        val leftGroups = if (doubleColonParts[0].isEmpty()) emptyList() else doubleColonParts[0].split(':')
        val rightGroups = if (!hasCompression || doubleColonParts[1].isEmpty()) emptyList() else doubleColonParts[1].split(':')

        val allGroups = leftGroups + rightGroups
        if (allGroups.isEmpty()) return hasCompression && ip == "::"

        var totalSlots = 0
        for ((index, group) in allGroups.withIndex()) {
            val isLast = index == allGroups.lastIndex
            if (group.contains('.')) {
                if (!isLast || !isValidIpv4(group)) return false
                totalSlots += 2
            } else {
                if (!HEX_GROUP_REGEX.matches(group)) return false
                totalSlots += 1
            }
        }

        return if (hasCompression) totalSlots < 8 else totalSlots == 8
    }

    fun isValidIp(raw: String): Boolean {
        val normalized = normalizeIp(raw)
        return isValidIpv4(normalized) || isValidIpv6(normalized)
    }

    fun isIpv6(raw: String): Boolean = isValidIpv6(normalizeIp(raw))

    fun isValidPort(port: Int?): Boolean = port == null || port in 1..65535
}

data class IncomingRule(
    val sourceIp: String,
    val protocol: IncomingProtocol = IncomingProtocol.ANY,
    val dstPort: Int? = null,
    val verdict: IncomingVerdict,
    val createdAt: Long = System.currentTimeMillis(),
    val note: String? = null
) {
    val normalizedIp: String get() = IpValidation.normalizeIp(sourceIp)

    val effectivePort: Int? get() = if (protocol.supportsPort()) dstPort else null

    val id: String get() = "$normalizedIp|${protocol.name}|${effectivePort ?: 0}"

    val specificity: Int
        get() = when {
            protocol != IncomingProtocol.ANY && effectivePort != null -> 3
            protocol != IncomingProtocol.ANY -> 2
            else -> 1
        }

    fun matches(eventIp: String, eventProtocol: IncomingProtocol, eventDstPort: Int?): Boolean {
        if (!normalizedIp.equals(IpValidation.normalizeIp(eventIp), ignoreCase = true)) return false
        if (!protocol.matches(eventProtocol)) return false
        val port = effectivePort
        if (port != null && eventDstPort != port) return false
        return true
    }

    fun scopeLabel(): String = when {
        protocol == IncomingProtocol.ANY -> "All traffic"
        effectivePort != null -> "${protocol.displayName} :$effectivePort"
        else -> protocol.displayName
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("sourceIp", normalizedIp)
        put("protocol", protocol.name)
        effectivePort?.let { put("dstPort", it) }
        put("verdict", verdict.name)
        put("createdAt", createdAt)
        if (!note.isNullOrBlank()) put("note", note)
    }

    companion object {
        fun fromJson(obj: JSONObject): IncomingRule? {
            val ip = IpValidation.normalizeIp(obj.optString("sourceIp", ""))
            if (!IpValidation.isValidIp(ip)) return null
            val verdict = IncomingVerdict.fromName(obj.optString("verdict", "")) ?: return null
            val protocol = IncomingProtocol.fromName(obj.optString("protocol", IncomingProtocol.ANY.name))
            val rawPort = if (obj.has("dstPort") && !obj.isNull("dstPort")) obj.optInt("dstPort", -1) else null
            val port = rawPort?.takeIf { it in 1..65535 && protocol.supportsPort() }
            val createdAt = obj.optLong("createdAt", 0L)
            val note = obj.optString("note", "").takeIf { it.isNotBlank() }
            return IncomingRule(
                sourceIp = ip,
                protocol = protocol,
                dstPort = port,
                verdict = verdict,
                createdAt = createdAt,
                note = note
            )
        }
    }
}

data class IncomingEvent(
    val id: Long,
    val timestamp: Long,
    val sourceIp: String,
    val destIp: String? = null,
    val protocol: IncomingProtocol,
    val srcPort: Int? = null,
    val dstPort: Int? = null,
    val interfaceName: String? = null,
    val enforced: Boolean,
    val discoveryLabel: String? = null,
    val verdict: IncomingVerdict? = null,
    val hitCount: Int = 1
) {
    fun detailSummary(): String {
        val base = discoveryLabel ?: protocol.displayName
        return when {
            dstPort != null && discoveryLabel != null -> "$base (:${dstPort})"
            dstPort != null -> "$base :$dstPort"
            else -> base
        }
    }
}
