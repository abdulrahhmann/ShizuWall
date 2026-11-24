package com.arslan.shizuwall.incoming

data class ParsedIncomingPacket(
    val sourceIp: String,
    val destIp: String?,
    val protocol: IncomingProtocol,
    val srcPort: Int?,
    val dstPort: Int?,
    val interfaceName: String?,
    val discoveryLabel: String?
)

object IncomingLogParser {

    fun parseKernelLogLine(line: String): ParsedIncomingPacket? {
        val markerIdx = line.indexOf(IncomingIptables.LOG_PREFIX)
        if (markerIdx < 0) return null

        val payload = line.substring(markerIdx + IncomingIptables.LOG_PREFIX.length).trim()
        if (payload.isEmpty()) return null

        var inIface: String? = null
        var src: String? = null
        var dst: String? = null
        var rawProto: String? = null
        var spt: Int? = null
        var dpt: Int? = null
        var icmpType: Int? = null

        for (token in payload.split(' ')) {
            val eq = token.indexOf('=')
            if (eq <= 0 || eq == token.lastIndex) continue
            val key = token.substring(0, eq)
            val value = token.substring(eq + 1)
            when (key) {
                "IN" -> inIface = value
                "SRC" -> src = value
                "DST" -> dst = value
                "PROTO" -> rawProto = value
                "SPT" -> spt = value.toIntOrNull()?.takeIf { it in 1..65535 }
                "DPT" -> dpt = value.toIntOrNull()?.takeIf { it in 1..65535 }
                "TYPE" -> icmpType = value.toIntOrNull()
            }
        }

        val normalizedSrc = src?.let { IpValidation.normalizeIp(it) } ?: return null
        if (!IpValidation.isValidIp(normalizedSrc)) return null
        val normalizedDst = dst?.let { IpValidation.normalizeIp(it) }?.takeIf { IpValidation.isValidIp(it) }

        val protoUpper = rawProto?.uppercase().orEmpty()
        val protocol = when (protoUpper) {
            "TCP", "6" -> IncomingProtocol.TCP
            "UDP", "17" -> IncomingProtocol.classifyUdpPort(dpt)
            "ICMP", "ICMPV6", "1", "58" -> IncomingProtocol.ICMP
            else -> IncomingProtocol.ANY
        }

        val discoveryLabel = when (protocol) {
            IncomingProtocol.MDNS -> "mDNS Network Discovery"
            IncomingProtocol.SSDP -> "SSDP / UPnP Discovery"
            IncomingProtocol.NETBIOS -> "NetBIOS Discovery"
            IncomingProtocol.WSD -> "WS-Discovery"
            IncomingProtocol.ICMP -> when {
                (protoUpper == "ICMP" || protoUpper == "1") && icmpType == 8 -> "Ping / ICMP Echo Request"
                (protoUpper == "ICMPV6" || protoUpper == "58") && icmpType == 128 -> "Ping / ICMPv6 Echo Request"
                else -> "ICMP Network Probe"
            }
            else -> null
        }

        return ParsedIncomingPacket(
            sourceIp = normalizedSrc,
            destIp = normalizedDst,
            protocol = protocol,
            srcPort = spt,
            dstPort = dpt,
            interfaceName = inIface,
            discoveryLabel = discoveryLabel
        )
    }
}
