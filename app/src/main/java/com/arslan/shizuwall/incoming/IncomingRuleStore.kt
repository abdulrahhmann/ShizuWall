package com.arslan.shizuwall.incoming

import android.content.Context
import android.content.SharedPreferences
import com.arslan.shizuwall.ui.MainActivity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import java.util.concurrent.atomic.AtomicLong

object IncomingRuleStore {

    const val KEY_INCOMING_GUARD_ENABLED = "incoming_guard_enabled"
    const val KEY_INCOMING_ALERT_DISCOVERY = "incoming_guard_alert_discovery"
    const val KEY_INCOMING_FILTER_IPV6 = "incoming_guard_filter_ipv6"
    const val KEY_INCOMING_RULES = "incoming_guard_rules_json"

    private const val MAX_EVENTS = 200
    private const val COALESCE_WINDOW_MS = 10_000L

    private val eventIdGen = AtomicLong(1L)
    private val lock = Any()

    private val _rules = MutableStateFlow<List<IncomingRule>>(emptyList())
    val rules: StateFlow<List<IncomingRule>> = _rules.asStateFlow()

    private val _events = MutableStateFlow<List<IncomingEvent>>(emptyList())
    val events: StateFlow<List<IncomingEvent>> = _events.asStateFlow()

    private val _activeMode = MutableStateFlow(GuardMode.STOPPED)
    val activeMode: StateFlow<GuardMode> = _activeMode.asStateFlow()

    enum class GuardMode {
        STOPPED,
        ROOT_ENFORCING,
        NON_ROOT_DISCOVERY_MONITOR
    }

    fun setActiveMode(mode: GuardMode) {
        _activeMode.value = mode
    }

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(MainActivity.PREF_NAME, Context.MODE_PRIVATE)

    fun isEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_INCOMING_GUARD_ENABLED, false)

    fun setEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_INCOMING_GUARD_ENABLED, enabled).apply()
        try {
            context.createDeviceProtectedStorageContext()
                .getSharedPreferences(MainActivity.PREF_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(KEY_INCOMING_GUARD_ENABLED, enabled)
                .apply()
        } catch (_: Exception) {
        }
    }

    fun isDiscoveryAlertsEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_INCOMING_ALERT_DISCOVERY, true)

    fun setDiscoveryAlertsEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_INCOMING_ALERT_DISCOVERY, enabled).apply()
    }

    fun isIpv6FilteringEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_INCOMING_FILTER_IPV6, true)

    fun setIpv6FilteringEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_INCOMING_FILTER_IPV6, enabled).apply()
    }

    fun getRules(context: Context): List<IncomingRule> {
        val loaded = decodeRules(prefs(context).getString(KEY_INCOMING_RULES, null))
        synchronized(lock) {
            _rules.value = loaded
        }
        return loaded
    }

    fun upsertRule(context: Context, rule: IncomingRule): List<IncomingRule> {
        val normalized = rule.copy(
            sourceIp = IpValidation.normalizeIp(rule.sourceIp),
            dstPort = rule.effectivePort
        )
        require(IpValidation.isValidIp(normalized.sourceIp)) { "Invalid IP address: ${rule.sourceIp}" }
        require(IpValidation.isValidPort(normalized.dstPort)) { "Invalid port: ${rule.dstPort}" }

        val updated: List<IncomingRule>
        synchronized(lock) {
            val current = decodeRules(prefs(context).getString(KEY_INCOMING_RULES, null))
            updated = (current.filterNot { it.id == normalized.id } + normalized)
                .sortedWith(compareByDescending<IncomingRule> { it.createdAt }.thenBy { it.normalizedIp })
            saveRules(prefs(context), updated)
            _rules.value = updated

            _events.value = _events.value.map { event ->
                if (normalized.matches(event.sourceIp, event.protocol, event.dstPort)) {
                    event.copy(verdict = normalized.verdict)
                } else {
                    event
                }
            }
        }
        return updated
    }

    fun removeRule(context: Context, ruleId: String): List<IncomingRule> {
        val updated: List<IncomingRule>
        synchronized(lock) {
            val current = decodeRules(prefs(context).getString(KEY_INCOMING_RULES, null))
            updated = current.filterNot { it.id == ruleId }
            saveRules(prefs(context), updated)
            _rules.value = updated
        }
        return updated
    }

    fun clearRules(context: Context) {
        synchronized(lock) {
            saveRules(prefs(context), emptyList())
            _rules.value = emptyList()
        }
    }

    fun findRule(context: Context, sourceIp: String, protocol: IncomingProtocol, dstPort: Int?): IncomingRule? {
        val current = _rules.value.ifEmpty { getRules(context) }
        return findBestMatchingRule(current, sourceIp, protocol, dstPort)
    }

    fun recordEvent(
        sourceIp: String,
        destIp: String?,
        protocol: IncomingProtocol,
        srcPort: Int?,
        dstPort: Int?,
        interfaceName: String?,
        enforced: Boolean,
        discoveryLabel: String?,
        verdict: IncomingVerdict?,
        timestamp: Long = System.currentTimeMillis()
    ): IncomingEvent {
        val normalizedIp = IpValidation.normalizeIp(sourceIp)
        synchronized(lock) {
            val current = _events.value
            val existingIdx = current.indexOfFirst { ev ->
                ev.sourceIp == normalizedIp &&
                    ev.protocol == protocol &&
                    ev.dstPort == dstPort &&
                    (timestamp - ev.timestamp) <= COALESCE_WINDOW_MS
            }
            if (existingIdx >= 0) {
                val existing = current[existingIdx]
                val merged = existing.copy(
                    timestamp = timestamp,
                    hitCount = existing.hitCount + 1,
                    verdict = verdict ?: existing.verdict
                )
                val next = current.toMutableList().apply {
                    removeAt(existingIdx)
                    add(0, merged)
                }
                _events.value = next
                return merged
            }

            val created = IncomingEvent(
                id = eventIdGen.getAndIncrement(),
                timestamp = timestamp,
                sourceIp = normalizedIp,
                destIp = destIp?.let { IpValidation.normalizeIp(it) },
                protocol = protocol,
                srcPort = srcPort,
                dstPort = dstPort,
                interfaceName = interfaceName,
                enforced = enforced,
                discoveryLabel = discoveryLabel,
                verdict = verdict,
                hitCount = 1
            )
            val next = (listOf(created) + current).take(MAX_EVENTS)
            _events.value = next
            return created
        }
    }

    fun clearEvents() {
        synchronized(lock) {
            _events.value = emptyList()
        }
    }

    private fun saveRules(prefs: SharedPreferences, rules: List<IncomingRule>) {
        prefs.edit().putString(KEY_INCOMING_RULES, encodeRules(rules)).apply()
    }

    internal fun encodeRules(rules: List<IncomingRule>): String {
        val arr = JSONArray()
        rules.forEach { arr.put(it.toJson()) }
        return arr.toString()
    }

    internal fun decodeRules(raw: String?): List<IncomingRule> {
        if (raw.isNullOrBlank()) return emptyList()
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { i ->
                arr.optJSONObject(i)?.let { IncomingRule.fromJson(it) }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    internal fun findBestMatchingRule(
        rules: List<IncomingRule>,
        sourceIp: String,
        protocol: IncomingProtocol,
        dstPort: Int?
    ): IncomingRule? {
        return rules
            .filter { it.matches(sourceIp, protocol, dstPort) }
            .maxWithOrNull(
                compareBy<IncomingRule> { it.specificity }
                    .thenBy { if (it.protocol == protocol) 1 else 0 }
                    .thenBy { it.createdAt }
            )
    }
}
