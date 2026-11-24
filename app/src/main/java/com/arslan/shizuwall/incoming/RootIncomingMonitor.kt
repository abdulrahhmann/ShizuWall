package com.arslan.shizuwall.incoming

import android.os.SystemClock
import android.util.Log
import com.arslan.shizuwall.shell.RootShellExecutor
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Root-backed incoming connection interceptor using iptables/ip6tables INPUT/OUTPUT chains,
 * optional nftables/arptables ARP Layer-2 stealth, and live kernel log streaming.
 */
class RootIncomingMonitor(
    private val onPacket: (ParsedIncomingPacket) -> Unit
) {

    data class ApplyResult(
        val success: Boolean,
        val stealthStatus: IncomingRuleStore.StealthStatus
    )

    private val running = AtomicBoolean(false)

    @Volatile
    private var watcherProcess: Process? = null

    @Volatile
    private var watcherThread: Thread? = null

    suspend fun applyRules(
        rules: List<IncomingRule>,
        includeIpv6: Boolean,
        stealthLan: Boolean,
        gatewayIpv4: String?
    ): ApplyResult {
        val script = IncomingIptables.buildSetupScript(
            rules = rules,
            includeIpv6 = includeIpv6,
            stealthLan = stealthLan,
            gatewayIpv4 = gatewayIpv4
        )
        val result = RootShellExecutor().exec(script)
        if (!result.success) {
            Log.w(TAG, "Failed to apply incoming iptables rules (rc=${result.exitCode}): ${result.stderr}")
            return ApplyResult(false, IncomingRuleStore.StealthStatus())
        }

        var arpBackend: String? = null
        var resolvedGw: String? = gatewayIpv4
        var outboundOn = false
        for (line in result.stdout.lineSequence()) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith("SHIZUWALL_CAP_ARP=") -> {
                    val v = trimmed.removePrefix("SHIZUWALL_CAP_ARP=").trim()
                    arpBackend = v.takeIf { it == "nft" || it == "arptables" }
                }
                trimmed.startsWith("SHIZUWALL_CAP_OUT=") -> {
                    outboundOn = trimmed.removePrefix("SHIZUWALL_CAP_OUT=").trim() == "on"
                }
                trimmed.startsWith("SHIZUWALL_GW=") -> {
                    val v = trimmed.removePrefix("SHIZUWALL_GW=").trim()
                    if (IpValidation.isValidIpv4(v)) resolvedGw = v
                }
            }
        }
        return ApplyResult(
            success = true,
            stealthStatus = IncomingRuleStore.StealthStatus(
                arpBackend = arpBackend,
                gatewayIp = resolvedGw,
                outboundStealthActive = outboundOn
            )
        )
    }

    suspend fun teardown() {
        val script = IncomingIptables.buildTeardownScript()
        runCatching { RootShellExecutor().exec(script) }
            .onFailure { Log.w(TAG, "Teardown error", it) }
    }

    fun startLogWatcher() {
        if (!running.compareAndSet(false, true)) return
        val thread = Thread(::watchLoop, "IncomingKernelLogWatcher").apply {
            isDaemon = true
            start()
        }
        watcherThread = thread
    }

    fun stopLogWatcher() {
        if (!running.compareAndSet(true, false)) return
        runCatching { watcherProcess?.destroyForcibly() }
        watcherProcess = null
        runCatching { watcherThread?.interrupt() }
        watcherThread = null
    }

    private fun watchLoop() {
        var useDmesgFallback = false
        while (running.get()) {
            val cmd = if (!useDmesgFallback) {
                "logcat -b kernel -T 1 -v raw"
            } else {
                "dmesg -w"
            }
            val startedAt = SystemClock.elapsedRealtime()
            val ignoreInitialUntil = if (useDmesgFallback) startedAt + DMESG_WARMUP_MS else 0L

            try {
                val proc = ProcessBuilder("su", "-c", cmd)
                    .redirectErrorStream(true)
                    .start()
                watcherProcess = proc

                BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                    var line: String?
                    while (running.get()) {
                        line = reader.readLine() ?: break
                        if (ignoreInitialUntil > 0L && SystemClock.elapsedRealtime() < ignoreInitialUntil) {
                            continue
                        }
                        if (!line.contains(IncomingIptables.LOG_PREFIX) &&
                            !line.contains(IncomingIptables.ARP_LOG_PREFIX)
                        ) {
                            continue
                        }
                        val parsed = IncomingLogParser.parseKernelLogLine(line) ?: continue
                        onPacket(parsed)
                    }
                }
                proc.waitFor()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            } catch (t: Throwable) {
                if (running.get()) {
                    Log.w(TAG, "Kernel log watcher error ($cmd): ${t.message}")
                }
            } finally {
                runCatching { watcherProcess?.destroyForcibly() }
                watcherProcess = null
            }

            if (!running.get()) break

            val elapsed = SystemClock.elapsedRealtime() - startedAt
            if (!useDmesgFallback && elapsed < 3_000L) {
                useDmesgFallback = true
                Log.d(TAG, "Switching kernel log watcher to dmesg -w fallback")
            } else {
                try {
                    Thread.sleep(RESTART_BACKOFF_MS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
        }
    }

    companion object {
        private const val TAG = "RootIncomingMonitor"
        private const val DMESG_WARMUP_MS = 800L
        private const val RESTART_BACKOFF_MS = 2_000L
    }
}
