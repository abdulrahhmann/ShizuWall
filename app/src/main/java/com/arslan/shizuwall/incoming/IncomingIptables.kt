package com.arslan.shizuwall.incoming

object IncomingIptables {

    const val CHAIN_V4 = "SHIZUWALL_IN"
    const val CHAIN_V6 = "SHIZUWALL_IN6"
    const val OUT_CHAIN_V4 = "SHIZUWALL_OUT"
    const val OUT_CHAIN_V6 = "SHIZUWALL_OUT6"
    const val ARP_TABLE_NFT = "shizuwall_arp"
    const val ARP_CHAIN_LEGACY = "SHIZUWALL_ARP"
    const val LOG_PREFIX = "[SHIZUWALL_IN] "
    const val ARP_LOG_PREFIX = "[SHIZUWALL_ARP] "

    private val ESSENTIAL_ICMPV6_TYPES = listOf(1, 2, 3, 4, 133, 134, 135, 136)
    private val OUTBOUND_DISCOVERY_UDP_PORTS = listOf("5353", "1900", "3702", "137:138", "5355")

    fun buildSetupScript(
        rules: List<IncomingRule>,
        includeIpv6: Boolean = true,
        stealthLan: Boolean = true,
        gatewayIpv4: String? = null
    ): String {
        val validGateway = gatewayIpv4
            ?.let { IpValidation.normalizeIp(it) }
            ?.takeIf { IpValidation.isValidIpv4(it) }

        val allowedIpv4s = rules
            .filter { it.verdict == IncomingVerdict.ALLOW && IpValidation.isValidIpv4(it.normalizedIp) }
            .map { it.normalizedIp }
            .distinct()

        val allowedIpv6s = rules
            .filter { it.verdict == IncomingVerdict.ALLOW && IpValidation.isValidIpv6(it.normalizedIp) }
            .map { it.normalizedIp }
            .distinct()

        val lines = mutableListOf<String>()
        lines += buildChainScript(
            binary = "iptables",
            chain = CHAIN_V4,
            rules = rules.filter { IpValidation.isValidIpv4(it.normalizedIp) },
            ipv6 = false
        )
        if (includeIpv6) {
            lines += buildChainScript(
                binary = "ip6tables",
                chain = CHAIN_V6,
                rules = rules.filter { IpValidation.isValidIpv6(it.normalizedIp) },
                ipv6 = true
            )
        } else {
            lines += buildTeardownChainLines("ip6tables", "INPUT", CHAIN_V6)
        }

        if (stealthLan) {
            lines += buildOutboundStealthScript("iptables", OUT_CHAIN_V4, allowedIpv4s, ipv6 = false)
            if (includeIpv6) {
                lines += buildOutboundStealthScript("ip6tables", OUT_CHAIN_V6, allowedIpv6s, ipv6 = true)
            } else {
                lines += buildTeardownChainLines("ip6tables", "OUTPUT", OUT_CHAIN_V6)
            }
            lines += "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null 2>&1 || true"
            lines += buildArpStealthScript(validGateway, allowedIpv4s)
        } else {
            lines += buildTeardownChainLines("iptables", "OUTPUT", OUT_CHAIN_V4)
            lines += buildTeardownChainLines("ip6tables", "OUTPUT", OUT_CHAIN_V6)
            lines += buildArpTeardownLines()
            lines += "echo SHIZUWALL_CAP_OUT=off"
            lines += "echo SHIZUWALL_CAP_ARP=off"
        }

        // Final status check confirms IPv4 INPUT hook is active.
        lines += "iptables -w -C INPUT -j $CHAIN_V4"
        return lines.joinToString("\n")
    }

    fun buildTeardownScript(): String {
        val lines = mutableListOf<String>()
        lines += buildTeardownChainLines("iptables", "INPUT", CHAIN_V4)
        lines += buildTeardownChainLines("ip6tables", "INPUT", CHAIN_V6)
        lines += buildTeardownChainLines("iptables", "OUTPUT", OUT_CHAIN_V4)
        lines += buildTeardownChainLines("ip6tables", "OUTPUT", OUT_CHAIN_V6)
        lines += buildArpTeardownLines()
        lines += "true"
        return lines.joinToString("\n")
    }

    internal fun buildUserRuleLines(binary: String, chain: String, rules: List<IncomingRule>, ipv6: Boolean): List<String> {
        val sorted = rules
            .filter {
                it.protocol != IncomingProtocol.ARP &&
                    if (ipv6) IpValidation.isValidIpv6(it.normalizedIp) else IpValidation.isValidIpv4(it.normalizedIp)
            }
            .sortedWith(compareByDescending<IncomingRule> { it.specificity }.thenBy { it.createdAt })

        return sorted.mapNotNull { rule ->
            val ip = rule.normalizedIp
            val target = when (rule.verdict) {
                IncomingVerdict.ALLOW -> "RETURN"
                IncomingVerdict.DENY -> "DROP"
            }
            val proto = rule.protocol.iptablesProtocol(ipv6)
            val port = rule.effectivePort
            val cmd = StringBuilder("$binary -w -A $chain -s $ip")
            if (proto != null) {
                cmd.append(" -p ").append(proto)
                if (port != null && (proto == "tcp" || proto == "udp")) {
                    cmd.append(" --dport ").append(port)
                }
            }
            cmd.append(" -j ").append(target)
            cmd.toString()
        }
    }

    private fun buildChainScript(
        binary: String,
        chain: String,
        rules: List<IncomingRule>,
        ipv6: Boolean
    ): List<String> {
        val out = mutableListOf<String>()
        val quietSuffix = if (ipv6) " 2>/dev/null || true" else ""
        out += "$binary -w -N $chain 2>/dev/null || true"
        out += "$binary -w -F $chain$quietSuffix"

        // Safe baseline: never break loopback, established outbound replies, DHCP, or IPv6 NDP.
        out += "$binary -w -A $chain -i lo -j RETURN$quietSuffix"
        out += "($binary -w -A $chain -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || " +
            "$binary -w -A $chain -m state --state ESTABLISHED,RELATED -j RETURN)$quietSuffix"

        if (!ipv6) {
            out += "$binary -w -A $chain -p udp --sport 67 --dport 68 -j RETURN"
        } else {
            out += "$binary -w -A $chain -p udp --sport 547 --dport 546 -j RETURN 2>/dev/null || true"
            for (type in ESSENTIAL_ICMPV6_TYPES) {
                out += "$binary -w -A $chain -p icmpv6 --icmpv6-type $type -j RETURN 2>/dev/null || true"
            }
        }

        // User-defined Allow / Deny rules (most specific first).
        for (ruleLine in buildUserRuleLines(binary, chain, rules, ipv6)) {
            out += "$ruleLine$quietSuffix"
        }

        // Log unsolicited incoming packets (rate-limited) and drop by default.
        out += "($binary -w -A $chain -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix \"$LOG_PREFIX\" --log-level 4 2>/dev/null || " +
            "$binary -w -A $chain -j LOG --log-prefix \"$LOG_PREFIX\" --log-level 4 2>/dev/null || true)"
        out += "$binary -w -A $chain -j DROP$quietSuffix"

        // Ensure single jump at the top of INPUT chain.
        out += "($binary -w -C INPUT -j $chain 2>/dev/null || $binary -w -I INPUT 1 -j $chain)$quietSuffix"
        return out
    }

    /**
     * Suppresses outbound LAN discovery broadcasts (mDNS, SSDP, WS-Discovery, NetBIOS, LLMNR)
     * so Android system services/apps do not announce this device's presence on the local network.
     */
    private fun buildOutboundStealthScript(
        binary: String,
        chain: String,
        allowedDstIps: List<String>,
        ipv6: Boolean
    ): List<String> {
        val out = mutableListOf<String>()
        val quietSuffix = " 2>/dev/null || true"
        out += "$binary -w -N $chain 2>/dev/null || true"
        out += "$binary -w -F $chain$quietSuffix"
        out += "$binary -w -A $chain -o lo -j RETURN$quietSuffix"

        for (ip in allowedDstIps) {
            out += "$binary -w -A $chain -d $ip -j RETURN$quietSuffix"
        }

        for (portSpec in OUTBOUND_DISCOVERY_UDP_PORTS) {
            out += "$binary -w -A $chain -p udp --dport $portSpec -j DROP$quietSuffix"
        }

        out += "($binary -w -C OUTPUT -j $chain 2>/dev/null || $binary -w -I OUTPUT 1 -j $chain)$quietSuffix"
        if (!ipv6) {
            out += "if iptables -w -C OUTPUT -j $chain 2>/dev/null; then echo SHIZUWALL_CAP_OUT=on; else echo SHIZUWALL_CAP_OUT=off; fi"
        }
        return out
    }

    /**
     * Drops Layer-2 ARP discovery requests from non-gateway LAN hosts while keeping
     * the router/gateway and explicitly allowed IPs reachable.
     * Tries nftables (arp family, supports logging) first, then arptables fallback.
     */
    private fun buildArpStealthScript(knownGateway: String?, allowedIpv4s: List<String>): List<String> {
        val out = mutableListOf<String>()
        out += buildArpTeardownLines()
        if (knownGateway != null) {
            out += "GW=$knownGateway"
        } else {
            out += "GW=\$(ip -4 route show default 2>/dev/null | awk '/default via/ {print \$3; exit}')"
            out += "if [ -z \"\$GW\" ]; then GW=\$(ip -4 route show table all 2>/dev/null | awk '/default via/ {print \$3; exit}'); fi"
        }
        out += "echo \"SHIZUWALL_GW=\$GW\""
        out += "ARP_MODE=none"
        out += "if [ -n \"\$GW\" ]; then"
        out += "  if command -v nft >/dev/null 2>&1 && nft add table arp $ARP_TABLE_NFT 2>/dev/null; then"
        out += "    nft add chain arp $ARP_TABLE_NFT input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null"
        out += "    nft add rule arp $ARP_TABLE_NFT input arp saddr ip \$GW accept 2>/dev/null"
        for (ip in allowedIpv4s) {
            out += "    nft add rule arp $ARP_TABLE_NFT input arp saddr ip $ip accept 2>/dev/null"
        }
        out += "    nft add rule arp $ARP_TABLE_NFT input arp operation request limit rate 10/second log prefix \"$ARP_LOG_PREFIX\" drop 2>/dev/null || true"
        out += "    if nft add rule arp $ARP_TABLE_NFT input arp operation request drop 2>/dev/null; then ARP_MODE=nft; else nft delete table arp $ARP_TABLE_NFT 2>/dev/null || true; fi"
        out += "  fi"
        out += "  if [ \"\$ARP_MODE\" = \"none\" ] && command -v arptables >/dev/null 2>&1; then"
        out += "    arptables -N $ARP_CHAIN_LEGACY 2>/dev/null || true"
        out += "    arptables -F $ARP_CHAIN_LEGACY 2>/dev/null || true"
        out += "    arptables -A $ARP_CHAIN_LEGACY --source-ip \$GW -j RETURN 2>/dev/null"
        for (ip in allowedIpv4s) {
            out += "    arptables -A $ARP_CHAIN_LEGACY --source-ip $ip -j RETURN 2>/dev/null"
        }
        out += "    arptables -A $ARP_CHAIN_LEGACY --opcode Request -j DROP 2>/dev/null"
        out += "    if arptables -I INPUT 1 -j $ARP_CHAIN_LEGACY 2>/dev/null; then ARP_MODE=arptables; else arptables -F $ARP_CHAIN_LEGACY 2>/dev/null; arptables -X $ARP_CHAIN_LEGACY 2>/dev/null; fi"
        out += "  fi"
        out += "fi"
        out += "echo \"SHIZUWALL_CAP_ARP=\$ARP_MODE\""
        return out
    }

    private fun buildArpTeardownLines(): List<String> = listOf(
        "nft delete table arp $ARP_TABLE_NFT 2>/dev/null || true",
        "while arptables -D INPUT -j $ARP_CHAIN_LEGACY 2>/dev/null; do :; done",
        "arptables -F $ARP_CHAIN_LEGACY 2>/dev/null || true",
        "arptables -X $ARP_CHAIN_LEGACY 2>/dev/null || true"
    )

    private fun buildTeardownChainLines(binary: String, parent: String, chain: String): List<String> = listOf(
        "while $binary -w -D $parent -j $chain 2>/dev/null; do :; done",
        "$binary -w -F $chain 2>/dev/null || true",
        "$binary -w -X $chain 2>/dev/null || true"
    )
}
