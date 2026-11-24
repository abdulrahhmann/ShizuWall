package com.arslan.shizuwall.services

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.arslan.shizuwall.R
import com.arslan.shizuwall.WorkingMode
import com.arslan.shizuwall.incoming.IncomingEvent
import com.arslan.shizuwall.incoming.IncomingIptables
import com.arslan.shizuwall.incoming.IncomingProtocol
import com.arslan.shizuwall.incoming.IncomingRuleStore
import com.arslan.shizuwall.incoming.IncomingVerdict
import com.arslan.shizuwall.incoming.MulticastDiscoveryMonitor
import com.arslan.shizuwall.incoming.ParsedIncomingPacket
import com.arslan.shizuwall.incoming.RootIncomingMonitor
import com.arslan.shizuwall.receivers.IncomingActionReceiver
import com.arslan.shizuwall.shell.RootShellExecutor
import com.arslan.shizuwall.ui.IncomingGuardActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class IncomingGuardService : Service() {

    companion object {
        private const val TAG = "IncomingGuardService"

        const val CHANNEL_ID_STATUS = "incoming_guard_status_channel"
        const val CHANNEL_ID_ALERTS = "incoming_guard_alerts_channel"
        const val FOREGROUND_NOTIFICATION_ID = 4001
        const val ALERT_NOTIFICATION_ID_BASE = 4100

        const val ACTION_START = "com.arslan.shizuwall.incoming.ACTION_START"
        const val ACTION_RELOAD_RULES = "com.arslan.shizuwall.incoming.ACTION_RELOAD_RULES"

        private const val ALERT_COOLDOWN_MS = 15_000L

        fun sync(context: Context) {
            val intent = Intent(context, IncomingGuardService::class.java).apply {
                action = ACTION_START
            }
            if (IncomingRuleStore.isEnabled(context)) {
                context.startForegroundService(intent)
            } else {
                context.stopService(intent)
            }
        }

        fun reloadRules(context: Context) {
            if (!IncomingRuleStore.isEnabled(context)) return
            val intent = Intent(context, IncomingGuardService::class.java).apply {
                action = ACTION_RELOAD_RULES
            }
            runCatching { context.startForegroundService(intent) }
        }

        suspend fun teardownRootRulesBestEffort() {
            if (!RootShellExecutor.hasRootAccess()) return
            runCatching {
                RootShellExecutor().exec(IncomingIptables.buildTeardownScript())
            }
        }

        fun alertNotificationIdFor(sourceIp: String): Int =
            ALERT_NOTIFICATION_ID_BASE + (sourceIp.hashCode() and 0x7FFF)
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val engineMutex = Mutex()
    private val lastAlertByIp = ConcurrentHashMap<String, Long>()
    private val handledCount = AtomicInteger(0)

    private var rootMonitor: RootIncomingMonitor? = null
    private var multicastMonitor: MulticastDiscoveryMonitor? = null

    @Volatile
    private var activeMode: IncomingRuleStore.GuardMode = IncomingRuleStore.GuardMode.STOPPED

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        promoteToForeground()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        promoteToForeground()

        if (!IncomingRuleStore.isEnabled(this)) {
            stopSelf()
            return START_NOT_STICKY
        }

        val action = intent?.action ?: ACTION_START
        serviceScope.launch {
            engineMutex.withLock {
                when (action) {
                    ACTION_RELOAD_RULES -> applyOrRestartEngine()
                    else -> startOrRefreshEngine()
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        val prevRoot = rootMonitor
        val prevMulticast = multicastMonitor
        rootMonitor = null
        multicastMonitor = null
        activeMode = IncomingRuleStore.GuardMode.STOPPED
        IncomingRuleStore.setActiveMode(IncomingRuleStore.GuardMode.STOPPED)

        runCatching { prevMulticast?.stop() }
        runCatching { prevRoot?.stopLogWatcher() }
        if (prevRoot != null) {
            runCatching {
                runBlocking(Dispatchers.IO) {
                    prevRoot.teardown()
                }
            }
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private suspend fun startOrRefreshEngine() {
        val rules = IncomingRuleStore.getRules(this)
        val includeIpv6 = IncomingRuleStore.isIpv6FilteringEnabled(this)
        val wantRoot = WorkingMode.of(this) == WorkingMode.ROOT && RootShellExecutor.hasRootAccess()

        if (wantRoot) {
            multicastMonitor?.stop()
            multicastMonitor = null

            val monitor = rootMonitor ?: RootIncomingMonitor { packet ->
                handleIncomingPacket(packet, enforced = true)
            }.also { rootMonitor = it }

            val applied = monitor.applyRules(rules, includeIpv6)
            if (applied) {
                monitor.startLogWatcher()
                activeMode = IncomingRuleStore.GuardMode.ROOT_ENFORCING
                IncomingRuleStore.setActiveMode(activeMode)
                updateStatusNotification()
                Log.d(TAG, "Incoming guard running in ROOT_ENFORCING mode (${rules.size} rules)")
                return
            }
            Log.w(TAG, "Root iptables apply failed; falling back to non-root multicast discovery monitor")
            monitor.stopLogWatcher()
            rootMonitor = null
        } else if (rootMonitor != null) {
            rootMonitor?.stopLogWatcher()
            rootMonitor?.teardown()
            rootMonitor = null
        }

        if (multicastMonitor == null) {
            multicastMonitor = MulticastDiscoveryMonitor(this) { packet ->
                handleIncomingPacket(packet, enforced = false)
            }.also { it.start() }
        }
        activeMode = IncomingRuleStore.GuardMode.NON_ROOT_DISCOVERY_MONITOR
        IncomingRuleStore.setActiveMode(activeMode)
        updateStatusNotification()
        Log.d(TAG, "Incoming guard running in NON_ROOT_DISCOVERY_MONITOR mode")
    }

    private suspend fun applyOrRestartEngine() {
        val rules = IncomingRuleStore.getRules(this)
        val includeIpv6 = IncomingRuleStore.isIpv6FilteringEnabled(this)
        val wantRoot = WorkingMode.of(this) == WorkingMode.ROOT && RootShellExecutor.hasRootAccess()

        val activeRoot = rootMonitor
        if (wantRoot && activeMode == IncomingRuleStore.GuardMode.ROOT_ENFORCING && activeRoot != null) {
            val applied = activeRoot.applyRules(rules, includeIpv6)
            if (applied) {
                updateStatusNotification()
                return
            }
        }
        startOrRefreshEngine()
    }

    private fun handleIncomingPacket(packet: ParsedIncomingPacket, enforced: Boolean) {
        val matchingRule = IncomingRuleStore.findRule(
            this,
            packet.sourceIp,
            packet.protocol,
            packet.dstPort
        )

        val event = IncomingRuleStore.recordEvent(
            sourceIp = packet.sourceIp,
            destIp = packet.destIp,
            protocol = packet.protocol,
            srcPort = packet.srcPort,
            dstPort = packet.dstPort,
            interfaceName = packet.interfaceName,
            enforced = enforced,
            discoveryLabel = packet.discoveryLabel,
            verdict = matchingRule?.verdict
        )

        // If a rule already exists for this peer/port, do not alert again.
        if (matchingRule != null) return

        // Respect user toggle for LAN discovery alerts.
        if (packet.protocol.isDiscovery && !IncomingRuleStore.isDiscoveryAlertsEnabled(this)) return

        handledCount.incrementAndGet()
        updateStatusNotification()
        postIncomingAlertNotification(event)
    }

    private fun postIncomingAlertNotification(event: IncomingEvent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        val now = System.currentTimeMillis()
        val prevAlert = lastAlertByIp[event.sourceIp] ?: 0L
        val silentUpdate = (now - prevAlert) < ALERT_COOLDOWN_MS
        if (!silentUpdate) {
            lastAlertByIp[event.sourceIp] = now
        }

        val notificationId = alertNotificationIdFor(event.sourceIp)
        val isDiscovery = event.discoveryLabel != null
        val title = when {
            event.enforced && isDiscovery -> getString(R.string.incoming_notif_discovery_blocked_title, event.sourceIp)
            event.enforced -> getString(R.string.incoming_notif_connection_blocked_title, event.sourceIp)
            else -> getString(R.string.incoming_notif_discovery_detected_title, event.sourceIp)
        }

        val details = buildString {
            append(event.detailSummary())
            if (!event.interfaceName.isNullOrBlank()) {
                append(" · ").append(event.interfaceName)
            }
            if (event.hitCount > 1) {
                append(" · ").append(getString(R.string.incoming_attempts_count, event.hitCount))
            }
            if (!event.enforced) {
                append(" · ").append(getString(R.string.incoming_monitor_only_badge))
            }
        }

        val openIntent = PendingIntent.getActivity(
            this,
            notificationId,
            Intent(this, IncomingGuardActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val allowIpIntent = buildActionPendingIntent(
            action = IncomingActionReceiver.ACTION_ALLOW_IP,
            requestCode = notificationId * 3 + 1,
            notificationId = notificationId,
            event = event
        )
        val denyIpIntent = buildActionPendingIntent(
            action = IncomingActionReceiver.ACTION_DENY_IP,
            requestCode = notificationId * 3 + 2,
            notificationId = notificationId,
            event = event
        )

        val builder = NotificationCompat.Builder(this, CHANNEL_ID_ALERTS)
            .setSmallIcon(R.drawable.ic_quick_tile)
            .setContentTitle(title)
            .setContentText(details)
            .setStyle(NotificationCompat.BigTextStyle().bigText(details))
            .setContentIntent(openIntent)
            .setAutoCancel(true)
            .setOnlyAlertOnce(silentUpdate)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .addAction(0, getString(R.string.incoming_action_allow), allowIpIntent)
            .addAction(0, getString(R.string.incoming_action_deny), denyIpIntent)

        val port = event.dstPort
        if (port != null && (event.protocol == IncomingProtocol.TCP || event.protocol == IncomingProtocol.UDP)) {
            val allowPortIntent = buildActionPendingIntent(
                action = IncomingActionReceiver.ACTION_ALLOW_PORT,
                requestCode = notificationId * 3 + 3,
                notificationId = notificationId,
                event = event
            )
            builder.addAction(
                0,
                getString(R.string.incoming_action_allow_port, port),
                allowPortIntent
            )
        }

        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(notificationId, builder.build())
    }

    private fun buildActionPendingIntent(
        action: String,
        requestCode: Int,
        notificationId: Int,
        event: IncomingEvent
    ): PendingIntent {
        val intent = Intent(this, IncomingActionReceiver::class.java).apply {
            this.action = action
            putExtra(IncomingActionReceiver.EXTRA_SOURCE_IP, event.sourceIp)
            putExtra(IncomingActionReceiver.EXTRA_PROTOCOL, event.protocol.name)
            event.dstPort?.let { putExtra(IncomingActionReceiver.EXTRA_DST_PORT, it) }
            putExtra(IncomingActionReceiver.EXTRA_NOTIFICATION_ID, notificationId)
        }
        return PendingIntent.getBroadcast(
            this,
            requestCode,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun promoteToForeground() {
        val notification = createStatusNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                FOREGROUND_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(FOREGROUND_NOTIFICATION_ID, notification)
        }
    }

    private fun createStatusNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, IncomingGuardActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val title = when (activeMode) {
            IncomingRuleStore.GuardMode.ROOT_ENFORCING ->
                getString(R.string.incoming_status_root_title)
            IncomingRuleStore.GuardMode.NON_ROOT_DISCOVERY_MONITOR ->
                getString(R.string.incoming_status_monitor_title)
            IncomingRuleStore.GuardMode.STOPPED ->
                getString(R.string.incoming_guard_title)
        }

        val count = handledCount.get()
        val body = when {
            activeMode == IncomingRuleStore.GuardMode.ROOT_ENFORCING && count > 0 ->
                getString(R.string.incoming_status_root_count, count)
            activeMode == IncomingRuleStore.GuardMode.ROOT_ENFORCING ->
                getString(R.string.incoming_status_root_idle)
            activeMode == IncomingRuleStore.GuardMode.NON_ROOT_DISCOVERY_MONITOR && count > 0 ->
                getString(R.string.incoming_status_monitor_count, count)
            else ->
                getString(R.string.incoming_status_monitor_idle)
        }

        return NotificationCompat.Builder(this, CHANNEL_ID_STATUS)
            .setSmallIcon(R.drawable.ic_quick_tile)
            .setContentTitle(title)
            .setContentText(body)
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateStatusNotification() {
        try {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.notify(FOREGROUND_NOTIFICATION_ID, createStatusNotification())
        } catch (_: Exception) {
        }
    }

    private fun createNotificationChannels() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        val statusChannel = NotificationChannel(
            CHANNEL_ID_STATUS,
            getString(R.string.incoming_status_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.incoming_status_channel_description)
            setShowBadge(false)
        }
        nm.createNotificationChannel(statusChannel)

        val alertsChannel = NotificationChannel(
            CHANNEL_ID_ALERTS,
            getString(R.string.incoming_alerts_channel_name),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = getString(R.string.incoming_alerts_channel_description)
            enableVibration(true)
        }
        nm.createNotificationChannel(alertsChannel)
    }
}
