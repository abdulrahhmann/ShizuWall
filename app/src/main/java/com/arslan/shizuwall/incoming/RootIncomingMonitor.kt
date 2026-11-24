package com.arslan.shizuwall.incoming

import android.os.SystemClock
import android.util.Log
import com.arslan.shizuwall.shell.RootShellExecutor
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Root-backed incoming connection interceptor using iptables/ip6tables INPUT chains
 * and live kernel log streaming.
 */
class RootIncomingMonitor(
    private val onPacket: (ParsedIncomingPacket) -> Unit
) {

    private val running = AtomicBoolean(false)

    @Volatile
    private var watcherProcess: Process? = null

    @Volatile
    private var watcherThread: Thread? = null

    suspend fun applyRules(rules: List<IncomingRule>, includeIpv6: Boolean): Boolean {
        val script = IncomingIptables.buildSetupScript(rules, includeIpv6)
        val result = RootShellExecutor().exec(script)
        if (!result.success) {
            Log.w(TAG, "Failed to apply incoming iptables rules (rc=${result.exitCode}): ${result.stderr}")
        }
        return result.success
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
                        if (!line.contains(IncomingIptables.LOG_PREFIX)) continue
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
