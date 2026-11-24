package com.arslan.shizuwall.incoming

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IncomingIptablesTest {

    @Test
    fun setupScriptIncludesSafeBaselineAndDefaultDrop() {
        val script = IncomingIptables.buildSetupScript(emptyList(), includeIpv6 = true)
        assertTrue(script.contains("iptables -w -N SHIZUWALL_IN"))
        assertTrue(script.contains("iptables -w -A SHIZUWALL_IN -i lo -j RETURN"))
        assertTrue(script.contains("--ctstate ESTABLISHED,RELATED -j RETURN"))
        assertTrue(script.contains("iptables -w -A SHIZUWALL_IN -p udp --sport 67 --dport 68 -j RETURN"))
        assertTrue(script.contains("--log-prefix \"[SHIZUWALL_IN] \""))
        assertTrue(script.contains("iptables -w -A SHIZUWALL_IN -j DROP"))
        assertTrue(script.contains("iptables -w -I INPUT 1 -j SHIZUWALL_IN"))
        assertTrue(script.contains("ip6tables -w -N SHIZUWALL_IN6"))
        assertTrue(script.contains("ip6tables -w -A SHIZUWALL_IN6 -p icmpv6 --icmpv6-type 135 -j RETURN"))
    }

    @Test
    fun userRulesOrderedMostSpecificFirstAndMappedToCorrectTargets() {
        val ipRule = IncomingRule("192.168.1.42", IncomingProtocol.ANY, null, IncomingVerdict.DENY, createdAt = 1L)
        val portRule = IncomingRule("192.168.1.42", IncomingProtocol.TCP, 8080, IncomingVerdict.ALLOW, createdAt = 2L)
        val v6Rule = IncomingRule("fe80::1", IncomingProtocol.ICMP, null, IncomingVerdict.ALLOW, createdAt = 3L)

        val v4Lines = IncomingIptables.buildUserRuleLines("iptables", IncomingIptables.CHAIN_V4, listOf(ipRule, portRule, v6Rule), ipv6 = false)
        assertEquals(2, v4Lines.size)
        assertEquals("iptables -w -A SHIZUWALL_IN -s 192.168.1.42 -p tcp --dport 8080 -j RETURN", v4Lines[0])
        assertEquals("iptables -w -A SHIZUWALL_IN -s 192.168.1.42 -j DROP", v4Lines[1])

        val v6Lines = IncomingIptables.buildUserRuleLines("ip6tables", IncomingIptables.CHAIN_V6, listOf(ipRule, portRule, v6Rule), ipv6 = true)
        assertEquals(1, v6Lines.size)
        assertEquals("ip6tables -w -A SHIZUWALL_IN6 -s fe80::1 -p icmpv6 -j RETURN", v6Lines[0])
    }

    @Test
    fun teardownRemovesJumpsAndDeletesBothChains() {
        val script = IncomingIptables.buildTeardownScript()
        assertTrue(script.contains("while iptables -w -D INPUT -j SHIZUWALL_IN"))
        assertTrue(script.contains("iptables -w -F SHIZUWALL_IN"))
        assertTrue(script.contains("iptables -w -X SHIZUWALL_IN"))
        assertTrue(script.contains("while ip6tables -w -D INPUT -j SHIZUWALL_IN6"))
        assertTrue(script.contains("ip6tables -w -X SHIZUWALL_IN6"))
    }

    @Test
    fun disablesIpv6ChainWhenFlagIsFalse() {
        val script = IncomingIptables.buildSetupScript(emptyList(), includeIpv6 = false)
        assertTrue(script.contains("while ip6tables -w -D INPUT -j SHIZUWALL_IN6"))
        assertFalse(script.contains("ip6tables -w -I INPUT 1 -j SHIZUWALL_IN6"))
    }

    @Test
    fun ipValidationAcceptsValidAndRejectsInjection() {
        assertTrue(IpValidation.isValidIp("192.168.1.1"))
        assertTrue(IpValidation.isValidIp("fe80::1%wlan0"))
        assertTrue(IpValidation.isValidIp("2001:db8::abcd:1"))
        assertFalse(IpValidation.isValidIp("192.168.1.1; rm -rf /"))
        assertFalse(IpValidation.isValidIp("999.1.1.1"))
        assertFalse(IpValidation.isValidIp("192.168.01.1"))
        assertFalse(IpValidation.isValidIp("not-an-ip"))
    }

    @Test
    fun ruleJsonRoundTripAndPrecedence() {
        val hostDeny = IncomingRule("192.168.1.50", IncomingProtocol.ANY, null, IncomingVerdict.DENY, createdAt = 10L)
        val udpAllow = IncomingRule("192.168.1.50", IncomingProtocol.UDP, null, IncomingVerdict.ALLOW, createdAt = 11L)
        val portDeny = IncomingRule("192.168.1.50", IncomingProtocol.MDNS, 5353, IncomingVerdict.DENY, createdAt = 12L)

        val encoded = IncomingRuleStore.encodeRules(listOf(hostDeny, udpAllow, portDeny))
        val decoded = IncomingRuleStore.decodeRules(encoded)
        assertEquals(3, decoded.size)

        val matchedMdns = IncomingRuleStore.findBestMatchingRule(decoded, "192.168.1.50", IncomingProtocol.MDNS, 5353)
        assertNotNull(matchedMdns)
        assertEquals(IncomingVerdict.DENY, matchedMdns!!.verdict)
        assertEquals(5353, matchedMdns.effectivePort)

        val matchedSsdp = IncomingRuleStore.findBestMatchingRule(decoded, "192.168.1.50", IncomingProtocol.SSDP, 1900)
        assertNotNull(matchedSsdp)
        assertEquals(IncomingVerdict.ALLOW, matchedSsdp!!.verdict)

        val matchedTcp = IncomingRuleStore.findBestMatchingRule(decoded, "192.168.1.50", IncomingProtocol.TCP, 22)
        assertNotNull(matchedTcp)
        assertEquals(IncomingVerdict.DENY, matchedTcp!!.verdict)

        assertNull(IncomingRuleStore.findBestMatchingRule(decoded, "192.168.1.99", IncomingProtocol.TCP, 22))
    }
}
