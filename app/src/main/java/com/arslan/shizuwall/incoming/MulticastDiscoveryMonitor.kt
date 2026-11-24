package com.arslan.shizuwall.incoming

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Passive LAN network-discovery monitor used when Root enforcement is unavailable.
 * Listens on standard multicast/broadcast discovery protocols (mDNS, SSDP, WS-Discovery,
 * and best-effort NetBIOS) and notifies the callback when another host probes the LAN.
 */
class MulticastDiscoveryMonitor(
    private val context: Context,
    private val onDiscovery: (ParsedIncomingPacket) -> Unit
) {

    private data class Endpoint(
        val groupIp: String?,
        val port: Int,
        val protocol: IncomingProtocol,
        val defaultLabel: String
    )

    private val running = AtomicBoolean(false)
    private val sockets = CopyOnWriteArrayList<DatagramSocket>()
    private val threads = CopyOnWriteArrayList<Thread>()
    private var multicastLock: WifiManager.MulticastLock? = null

    @Volatile
    private var localAddresses: Set<String> = emptySet()

    @Volatile
    private var lastLocalRefreshMs: Long = 0L

    fun start() {
        if (!running.compareAndSet(false, true)) return

        refreshLocalAddresses(force = true)
        acquireMulticastLock()

        for (endpoint in ENDPOINTS) {
            val thread = Thread({ listenLoop(endpoint) }, "IncomingDiscovery-${endpoint.protocol.name}").apply {
                isDaemon = true
                start()
            }
            threads.add(thread)
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return

        for (socket in sockets) {
            runCatching { socket.close() }
        }
        sockets.clear()

        for (thread in threads) {
            runCatching { thread.interrupt() }
        }
        threads.clear()

        releaseMulticastLock()
    }

    private fun acquireMulticastLock() {
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            val lock = wifiManager?.createMulticastLock("ShizuWallIncomingDiscovery")
            lock?.setReferenceCounted(false)
            lock?.acquire()
            multicastLock = lock
        } catch (t: Throwable) {
            Log.w(TAG, "Unable to acquire Wi-Fi multicast lock", t)
        }
    }

    private fun releaseMulticastLock() {
        try {
            multicastLock?.let {
                if (it.isHeld) it.release()
            }
        } catch (_: Throwable) {
        } finally {
            multicastLock = null
        }
    }

    private fun listenLoop(endpoint: Endpoint) {
        val socket = openSocket(endpoint) ?: return
        sockets.add(socket)
        val buffer = ByteArray(2048)

        try {
            while (running.get() && !socket.isClosed) {
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                val senderRaw = packet.address?.hostAddress ?: continue
                val senderIp = IpValidation.normalizeIp(senderRaw)
                if (!IpValidation.isValidIp(senderIp)) continue
                if (isLocalAddress(senderIp)) continue

                val label = classifyLabel(endpoint, packet.data, packet.length)
                onDiscovery(
                    ParsedIncomingPacket(
                        sourceIp = senderIp,
                        destIp = endpoint.groupIp,
                        protocol = endpoint.protocol,
                        srcPort = packet.port.takeIf { it in 1..65535 },
                        dstPort = endpoint.port,
                        interfaceName = null,
                        discoveryLabel = label
                    )
                )
            }
        } catch (_: Exception) {
            // Expected when socket is closed during stop() or network switches.
        } finally {
            runCatching { socket.close() }
            sockets.remove(socket)
        }
    }

    private fun openSocket(endpoint: Endpoint): DatagramSocket? {
        return try {
            if (endpoint.groupIp != null) {
                val ms = MulticastSocket(null)
                ms.reuseAddress = true
                ms.bind(InetSocketAddress(endpoint.port))
                val group = InetAddress.getByName(endpoint.groupIp)
                var joined = false
                try {
                    val ifaces = NetworkInterface.getNetworkInterfaces()
                    while (ifaces != null && ifaces.hasMoreElements()) {
                        val nif = ifaces.nextElement()
                        if (!nif.isUp || nif.isLoopback || !nif.supportsMulticast()) continue
                        runCatching {
                            ms.joinGroup(InetSocketAddress(group, endpoint.port), nif)
                            joined = true
                        }
                    }
                } catch (_: Throwable) {
                }
                if (!joined) {
                    @Suppress("DEPRECATION")
                    ms.joinGroup(group)
                }
                ms
            } else {
                DatagramSocket(null).apply {
                    reuseAddress = true
                    broadcast = true
                    bind(InetSocketAddress(endpoint.port))
                }
            }
        } catch (t: Throwable) {
            Log.d(TAG, "Skipping discovery endpoint ${endpoint.protocol}:${endpoint.port}: ${t.message}")
            null
        }
    }

    private fun classifyLabel(endpoint: Endpoint, data: ByteArray, length: Int): String {
        if (endpoint.protocol == IncomingProtocol.SSDP && length > 0) {
            val preview = String(data, 0, length.coerceAtMost(64), Charsets.US_ASCII)
            if (preview.startsWith("M-SEARCH", ignoreCase = true)) {
                return "SSDP M-SEARCH Discovery"
            }
        }
        return endpoint.defaultLabel
    }

    private fun isLocalAddress(ip: String): Boolean {
        if (ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" || ip == "::") return true
        refreshLocalAddresses(force = false)
        return ip in localAddresses
    }

    private fun refreshLocalAddresses(force: Boolean) {
        val now = System.currentTimeMillis()
        if (!force && (now - lastLocalRefreshMs) < LOCAL_ADDR_REFRESH_MS) return
        lastLocalRefreshMs = now
        val found = mutableSetOf<String>()
        try {
            val ifaces = NetworkInterface.getNetworkInterfaces()
            while (ifaces != null && ifaces.hasMoreElements()) {
                val nif = ifaces.nextElement()
                val addrs = nif.inetAddresses
                while (addrs.hasMoreElements()) {
                    addrs.nextElement().hostAddress?.let {
                        found.add(IpValidation.normalizeIp(it))
                    }
                }
            }
        } catch (_: Throwable) {
        }
        localAddresses = found
    }

    companion object {
        private const val TAG = "MulticastDiscoveryMon"
        private const val LOCAL_ADDR_REFRESH_MS = 30_000L

        private val ENDPOINTS = listOf(
            Endpoint("224.0.0.251", 5353, IncomingProtocol.MDNS, "mDNS Network Discovery"),
            Endpoint("239.255.255.250", 1900, IncomingProtocol.SSDP, "SSDP / UPnP Discovery"),
            Endpoint("239.255.255.250", 3702, IncomingProtocol.WSD, "WS-Discovery"),
            Endpoint(null, 137, IncomingProtocol.NETBIOS, "NetBIOS Discovery")
        )
    }
}
