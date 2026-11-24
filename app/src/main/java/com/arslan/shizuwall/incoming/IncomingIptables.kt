package com.arslan.shizuwall.incoming

object IncomingIptables {

    const val CHAIN_V4 = "SHIZUWALL_IN"
    const val CHAIN_V6 = "SHIZUWALL_IN6"
    const val LOG_PREFIX = "[SHIZUWALL_IN] "

    private val ESSENTIAL_ICMPV6_TYPES = listOf(1, 2, 3, 4, 133, 134, 135, 136)

    fun buildSetupScript(rules: List<IncomingRule>, includeIpv6: Boolean = true): String {
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
            lines += buildTeardownChainLines("ip6tables", CHAIN_V6)
        }
        // Final status check confirms IPv4 hook is active.
        lines += "iptables -w -C INPUT -j $CHAIN_V4"
        return lines.joinToString("\n")
    }

    fun buildTeardownScript(): String {
        val lines = mutableListOf<String>()
        lines += buildTeardownChainLines("iptables", CHAIN_V4)
        lines += buildTeardownChainLines("ip6tables", CHAIN_V6)
        lines += "true"
        return lines.joinToString("\n")
    }

    internal fun buildUserRuleLines(binary: String, chain: String, rules: List<IncomingRule>, ipv6: Boolean): List<String> {
        val sorted = rules
            .filter { if (ipv6) IpValidation.isValidIpv6(it.normalizedIp) else IpValidation.isValidIpv4(it.normalizedIp) }
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

    private fun buildTeardownChainLines(binary: String, chain: String): List<String> = listOf(
        "while $binary -w -D INPUT -j $chain 2>/dev/null; do :; done",
        "$binary -w -F $chain 2>/dev/null || true",
        "$binary -w -X $chain 2>/dev/null || true"
    )
}
