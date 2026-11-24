package com.arslan.shizuwall.incoming

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class IncomingLogParserTest {

    @Test
    fun parsesTcpIncomingSynLogLine() {
        val line = "<4>[12345.678] [SHIZUWALL_IN] IN=wlan0 OUT= MAC=aa:bb SRC=192.168.1.42 DST=192.168.1.105 LEN=60 PROTO=TCP SPT=54321 DPT=8080 WINDOW=64240 SYN"
        val parsed = IncomingLogParser.parseKernelLogLine(line)
        assertNotNull(parsed)
        assertEquals("192.168.1.42", parsed!!.sourceIp)
        assertEquals("192.168.1.105", parsed.destIp)
        assertEquals(IncomingProtocol.TCP, parsed.protocol)
        assertEquals(54321, parsed.srcPort)
        assertEquals(8080, parsed.dstPort)
        assertEquals("wlan0", parsed.interfaceName)
        assertNull(parsed.discoveryLabel)
    }

    @Test
    fun classifiesMdnsAndSsdpDiscoveryProbes() {
        val mdnsLine = "[SHIZUWALL_IN] IN=wlan0 OUT= SRC=192.168.1.10 DST=224.0.0.251 PROTO=UDP SPT=5353 DPT=5353 LEN=52"
        val mdns = IncomingLogParser.parseKernelLogLine(mdnsLine)
        assertNotNull(mdns)
        assertEquals(IncomingProtocol.MDNS, mdns!!.protocol)
        assertEquals("mDNS Network Discovery", mdns.discoveryLabel)

        val ssdpLine = "[SHIZUWALL_IN] IN=wlan0 OUT= SRC=192.168.1.15 DST=239.255.255.250 PROTO=UDP SPT=41000 DPT=1900 LEN=140"
        val ssdp = IncomingLogParser.parseKernelLogLine(ssdpLine)
        assertNotNull(ssdp)
        assertEquals(IncomingProtocol.SSDP, ssdp!!.protocol)
        assertEquals("SSDP / UPnP Discovery", ssdp.discoveryLabel)
    }

    @Test
    fun parsesIcmpAndIcmpv6EchoRequests() {
        val icmpLine = "[SHIZUWALL_IN] IN=wlan0 OUT= SRC=10.0.0.5 DST=10.0.0.20 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1"
        val icmp = IncomingLogParser.parseKernelLogLine(icmpLine)
        assertNotNull(icmp)
        assertEquals(IncomingProtocol.ICMP, icmp!!.protocol)
        assertEquals("Ping / ICMP Echo Request", icmp.discoveryLabel)

        val icmpv6Line = "[SHIZUWALL_IN] IN=wlan0 OUT= SRC=fe80::2 DST=fe80::1 PROTO=ICMPv6 TYPE=128 CODE=0"
        val icmpv6 = IncomingLogParser.parseKernelLogLine(icmpv6Line)
        assertNotNull(icmpv6)
        assertEquals("fe80::2", icmpv6!!.sourceIp)
        assertEquals(IncomingProtocol.ICMP, icmpv6.protocol)
        assertEquals("Ping / ICMPv6 Echo Request", icmpv6.discoveryLabel)
    }

    @Test
    fun parsesNftArpScanLogLine() {
        val line = "<4>[222.111] [SHIZUWALL_ARP] IN=wlan0 OUT= MAC=ff:ff:ff:ff:ff:ff SRC=192.168.1.88 DST=192.168.1.105"
        val parsed = IncomingLogParser.parseKernelLogLine(line)
        assertNotNull(parsed)
        assertEquals("192.168.1.88", parsed!!.sourceIp)
        assertEquals(IncomingProtocol.ARP, parsed.protocol)
        assertEquals("ARP Network Scan", parsed.discoveryLabel)
    }

    @Test
    fun ignoresUnrelatedOrMalformedLogLines() {
        assertNull(IncomingLogParser.parseKernelLogLine("audit: type=1400 avc: denied"))
        assertNull(IncomingLogParser.parseKernelLogLine("[SHIZUWALL_IN] IN=wlan0 SRC=not_an_ip PROTO=TCP"))
        assertNull(IncomingLogParser.parseKernelLogLine("[SHIZUWALL_IN] "))
    }
}
