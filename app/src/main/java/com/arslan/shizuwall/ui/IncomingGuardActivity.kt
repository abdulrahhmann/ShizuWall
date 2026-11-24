package com.arslan.shizuwall.ui

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.arslan.shizuwall.R
import com.arslan.shizuwall.WorkingMode
import com.arslan.shizuwall.incoming.IncomingEvent
import com.arslan.shizuwall.incoming.IncomingProtocol
import com.arslan.shizuwall.incoming.IncomingRule
import com.arslan.shizuwall.incoming.IncomingRuleStore
import com.arslan.shizuwall.incoming.IncomingVerdict
import com.arslan.shizuwall.incoming.IpValidation
import com.arslan.shizuwall.services.IncomingGuardService
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.button.MaterialButtonToggleGroup
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

class IncomingGuardActivity : BaseActivity() {

    private lateinit var switchIncomingGuard: MaterialSwitch
    private lateinit var switchAlertDiscovery: MaterialSwitch
    private lateinit var switchFilterIpv6: MaterialSwitch
    private lateinit var rowFilterIpv6: View
    private lateinit var tvModeTitle: TextView
    private lateinit var tvModeDesc: TextView
    private lateinit var toggleSection: MaterialButtonToggleGroup
    private lateinit var btnAddRule: MaterialButton
    private lateinit var btnClearList: MaterialButton
    private lateinit var tvEmptyState: TextView
    private lateinit var rvIncomingList: RecyclerView

    private val eventAdapter = IncomingEventAdapter(
        onAllowIp = { event -> applyRuleFromEvent(event, IncomingVerdict.ALLOW, perPort = false) },
        onDenyIp = { event -> applyRuleFromEvent(event, IncomingVerdict.DENY, perPort = false) },
        onAllowPort = { event -> applyRuleFromEvent(event, IncomingVerdict.ALLOW, perPort = true) }
    )

    private val ruleAdapter = IncomingRuleAdapter(
        onToggle = { rule ->
            val flipped = rule.copy(
                verdict = if (rule.verdict == IncomingVerdict.ALLOW) IncomingVerdict.DENY else IncomingVerdict.ALLOW
            )
            IncomingRuleStore.upsertRule(this, flipped)
            IncomingGuardService.reloadRules(this)
        },
        onDelete = { rule ->
            IncomingRuleStore.removeRule(this, rule.id)
            IncomingGuardService.reloadRules(this)
        }
    )

    private var showingRules = false
    private var suppressListeners = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        enableEdgeToEdge()
        setContentView(R.layout.activity_incoming_guard)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        setupSettingsChrome(R.id.incomingGuardRoot, toolbar)

        switchIncomingGuard = findViewById(R.id.switchIncomingGuard)
        switchAlertDiscovery = findViewById(R.id.switchAlertDiscovery)
        switchFilterIpv6 = findViewById(R.id.switchFilterIpv6)
        rowFilterIpv6 = findViewById(R.id.rowFilterIpv6)
        tvModeTitle = findViewById(R.id.tvModeTitle)
        tvModeDesc = findViewById(R.id.tvModeDesc)
        toggleSection = findViewById(R.id.toggleSection)
        btnAddRule = findViewById(R.id.btnAddRule)
        btnClearList = findViewById(R.id.btnClearList)
        tvEmptyState = findViewById(R.id.tvEmptyState)
        rvIncomingList = findViewById(R.id.rvIncomingList)

        rvIncomingList.layoutManager = LinearLayoutManager(this)
        rvIncomingList.adapter = eventAdapter

        loadInitialState()
        setupListeners()
        observeState()
    }

    override fun onResume() {
        super.onResume()
        IncomingRuleStore.getRules(this)
        updateModeBanner(IncomingRuleStore.activeMode.value)
    }

    private fun loadInitialState() {
        suppressListeners = true
        switchIncomingGuard.isChecked = IncomingRuleStore.isEnabled(this)
        switchAlertDiscovery.isChecked = IncomingRuleStore.isDiscoveryAlertsEnabled(this)
        switchFilterIpv6.isChecked = IncomingRuleStore.isIpv6FilteringEnabled(this)
        suppressListeners = false

        IncomingRuleStore.getRules(this)
        updateModeBanner(IncomingRuleStore.activeMode.value)
    }

    private fun setupListeners() {
        switchIncomingGuard.setOnCheckedChangeListener { _, isChecked ->
            if (suppressListeners) return@setOnCheckedChangeListener
            if (isChecked) requestNotificationPermissionIfNeeded()
            IncomingRuleStore.setEnabled(this, isChecked)
            IncomingGuardService.sync(this)
            updateModeBanner(IncomingRuleStore.activeMode.value)
        }

        switchAlertDiscovery.setOnCheckedChangeListener { _, isChecked ->
            if (suppressListeners) return@setOnCheckedChangeListener
            IncomingRuleStore.setDiscoveryAlertsEnabled(this, isChecked)
        }

        switchFilterIpv6.setOnCheckedChangeListener { _, isChecked ->
            if (suppressListeners) return@setOnCheckedChangeListener
            IncomingRuleStore.setIpv6FilteringEnabled(this, isChecked)
            IncomingGuardService.reloadRules(this)
        }

        toggleSection.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            showingRules = checkedId == R.id.btnTabRules
            btnAddRule.isVisible = showingRules
            rvIncomingList.adapter = if (showingRules) ruleAdapter else eventAdapter
            updateEmptyState()
        }

        btnAddRule.setOnClickListener { showAddRuleDialog() }

        btnClearList.setOnClickListener {
            if (showingRules) {
                if (IncomingRuleStore.rules.value.isEmpty()) return@setOnClickListener
                MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.incoming_clear_rules_title)
                    .setMessage(R.string.incoming_clear_rules_message)
                    .setPositiveButton(R.string.incoming_clear_confirm) { _, _ ->
                        IncomingRuleStore.clearRules(this)
                        IncomingGuardService.reloadRules(this)
                    }
                    .setNegativeButton(R.string.cancel, null)
                    .show()
            } else {
                IncomingRuleStore.clearEvents()
            }
        }

        listOf(switchIncomingGuard, switchAlertDiscovery, switchFilterIpv6)
            .forEach(::makeCardClickableForSwitch)
    }

    private fun observeState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    IncomingRuleStore.events.collect { events ->
                        eventAdapter.submit(events)
                        if (!showingRules) updateEmptyState()
                    }
                }
                launch {
                    IncomingRuleStore.rules.collect { rules ->
                        ruleAdapter.submit(rules)
                        if (showingRules) updateEmptyState()
                    }
                }
                launch {
                    IncomingRuleStore.activeMode.collect { mode ->
                        updateModeBanner(mode)
                    }
                }
            }
        }
    }

    private fun updateModeBanner(mode: IncomingRuleStore.GuardMode) {
        val isRootBackend = WorkingMode.of(this) == WorkingMode.ROOT
        rowFilterIpv6.isVisible = isRootBackend

        when (mode) {
            IncomingRuleStore.GuardMode.ROOT_ENFORCING -> {
                tvModeTitle.setText(R.string.incoming_mode_root_active_title)
                tvModeDesc.setText(R.string.incoming_mode_root_active_desc)
            }
            IncomingRuleStore.GuardMode.NON_ROOT_DISCOVERY_MONITOR -> {
                tvModeTitle.setText(R.string.incoming_mode_monitor_active_title)
                tvModeDesc.setText(R.string.incoming_mode_monitor_active_desc)
            }
            IncomingRuleStore.GuardMode.STOPPED -> {
                if (isRootBackend) {
                    tvModeTitle.setText(R.string.incoming_mode_root_ready_title)
                    tvModeDesc.setText(R.string.incoming_mode_root_ready_desc)
                } else {
                    tvModeTitle.setText(R.string.incoming_mode_monitor_ready_title)
                    tvModeDesc.setText(R.string.incoming_mode_monitor_ready_desc)
                }
            }
        }
    }

    private fun updateEmptyState() {
        val isEmpty = if (showingRules) {
            IncomingRuleStore.rules.value.isEmpty()
        } else {
            IncomingRuleStore.events.value.isEmpty()
        }
        tvEmptyState.isVisible = isEmpty
        rvIncomingList.isVisible = !isEmpty
        if (isEmpty) {
            tvEmptyState.setText(
                if (showingRules) R.string.incoming_empty_rules else R.string.incoming_empty_activity
            )
        }
    }

    private fun applyRuleFromEvent(event: IncomingEvent, verdict: IncomingVerdict, perPort: Boolean) {
        val protocol = if (perPort && event.protocol.supportsPort() && event.dstPort != null) {
            event.protocol
        } else {
            IncomingProtocol.ANY
        }
        val port = if (perPort && protocol.supportsPort()) event.dstPort else null

        val rule = IncomingRule(
            sourceIp = event.sourceIp,
            protocol = protocol,
            dstPort = port,
            verdict = verdict
        )
        IncomingRuleStore.upsertRule(this, rule)
        IncomingGuardService.reloadRules(this)

        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.cancel(IncomingGuardService.alertNotificationIdFor(event.sourceIp))

        val msg = when {
            verdict == IncomingVerdict.ALLOW && port != null ->
                getString(R.string.incoming_toast_allowed_port, event.sourceIp, protocol.displayName, port)
            verdict == IncomingVerdict.ALLOW ->
                getString(R.string.incoming_toast_allowed_ip, event.sourceIp)
            else ->
                getString(R.string.incoming_toast_denied_ip, event.sourceIp)
        }
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }

    private fun showAddRuleDialog() {
        val view = layoutInflater.inflate(R.layout.dialog_add_incoming_rule, null)
        val etIp = view.findViewById<TextInputEditText>(R.id.etRuleIp)
        val rgProto = view.findViewById<RadioGroup>(R.id.rgRuleProtocol)
        val tilPort = view.findViewById<TextInputLayout>(R.id.tilRulePort)
        val etPort = view.findViewById<TextInputEditText>(R.id.etRulePort)
        val rgVerdict = view.findViewById<RadioGroup>(R.id.rgRuleVerdict)

        rgProto.setOnCheckedChangeListener { _, checkedId ->
            val supportsPort = checkedId == R.id.rbProtoTcp || checkedId == R.id.rbProtoUdp
            tilPort.isVisible = supportsPort
            if (!supportsPort) etPort.setText("")
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.incoming_add_rule)
            .setView(view)
            .setPositiveButton(R.string.apply) { _, _ ->
                val rawIp = etIp.text?.toString().orEmpty().trim()
                val ip = IpValidation.normalizeIp(rawIp)
                if (!IpValidation.isValidIp(ip)) {
                    Toast.makeText(this, R.string.incoming_invalid_ip, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                val protocol = when (rgProto.checkedRadioButtonId) {
                    R.id.rbProtoTcp -> IncomingProtocol.TCP
                    R.id.rbProtoUdp -> IncomingProtocol.UDP
                    R.id.rbProtoIcmp -> IncomingProtocol.ICMP
                    else -> IncomingProtocol.ANY
                }
                val portRaw = etPort.text?.toString().orEmpty().trim()
                val port = if (protocol.supportsPort() && portRaw.isNotEmpty()) {
                    val parsed = portRaw.toIntOrNull()
                    if (parsed == null || parsed !in 1..65535) {
                        Toast.makeText(this, R.string.incoming_invalid_port, Toast.LENGTH_SHORT).show()
                        return@setPositiveButton
                    }
                    parsed
                } else {
                    null
                }
                val verdict = if (rgVerdict.checkedRadioButtonId == R.id.rbVerdictDeny) {
                    IncomingVerdict.DENY
                } else {
                    IncomingVerdict.ALLOW
                }
                IncomingRuleStore.upsertRule(
                    this,
                    IncomingRule(
                        sourceIp = ip,
                        protocol = protocol,
                        dstPort = port,
                        verdict = verdict
                    )
                )
                IncomingGuardService.reloadRules(this)
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1009)
            }
        }
    }

    private class IncomingEventAdapter(
        private val onAllowIp: (IncomingEvent) -> Unit,
        private val onDenyIp: (IncomingEvent) -> Unit,
        private val onAllowPort: (IncomingEvent) -> Unit
    ) : RecyclerView.Adapter<IncomingEventAdapter.Holder>() {

        private var items: List<IncomingEvent> = emptyList()
        private val timeFormat = DateFormat.getTimeInstance(DateFormat.MEDIUM)

        fun submit(next: List<IncomingEvent>) {
            items = next
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_incoming_event, parent, false)
            return Holder(view)
        }

        override fun onBindViewHolder(holder: Holder, position: Int) {
            holder.bind(items[position])
        }

        override fun getItemCount(): Int = items.size

        inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
            private val tvIp: TextView = view.findViewById(R.id.tvEventIp)
            private val tvStatus: TextView = view.findViewById(R.id.tvEventStatus)
            private val tvDetail: TextView = view.findViewById(R.id.tvEventDetail)
            private val tvMeta: TextView = view.findViewById(R.id.tvEventMeta)
            private val btnAllow: MaterialButton = view.findViewById(R.id.btnEventAllow)
            private val btnDeny: MaterialButton = view.findViewById(R.id.btnEventDeny)
            private val btnAllowPort: MaterialButton = view.findViewById(R.id.btnEventAllowPort)

            fun bind(event: IncomingEvent) {
                val ctx = itemView.context
                tvIp.text = event.sourceIp
                tvDetail.text = event.detailSummary()

                val statusRes = when (event.verdict) {
                    IncomingVerdict.ALLOW -> R.string.incoming_status_allowed
                    IncomingVerdict.DENY -> R.string.incoming_status_denied
                    null -> if (event.enforced) R.string.incoming_status_blocked else R.string.incoming_status_detected
                }
                tvStatus.setText(statusRes)
                val statusColorAttr = when (event.verdict) {
                    IncomingVerdict.ALLOW -> com.google.android.material.R.attr.colorPrimary
                    IncomingVerdict.DENY -> com.google.android.material.R.attr.colorError
                    null -> if (event.enforced) {
                        com.google.android.material.R.attr.colorError
                    } else {
                        com.google.android.material.R.attr.colorTertiary
                    }
                }
                tvStatus.setTextColor(MaterialColors.getColor(tvStatus, statusColorAttr))

                val metaParts = mutableListOf(timeFormat.format(Date(event.timestamp)))
                if (!event.interfaceName.isNullOrBlank()) metaParts += event.interfaceName
                if (event.hitCount > 1) metaParts += ctx.getString(R.string.incoming_attempts_count, event.hitCount)
                tvMeta.text = metaParts.joinToString(" · ")

                btnAllow.setOnClickListener { onAllowIp(event) }
                btnDeny.setOnClickListener { onDenyIp(event) }

                val port = event.dstPort
                if (port != null && (event.protocol == IncomingProtocol.TCP || event.protocol == IncomingProtocol.UDP)) {
                    btnAllowPort.isVisible = true
                    btnAllowPort.text = ctx.getString(R.string.incoming_action_allow_port, port)
                    btnAllowPort.setOnClickListener { onAllowPort(event) }
                } else {
                    btnAllowPort.isVisible = false
                }
            }
        }
    }

    private class IncomingRuleAdapter(
        private val onToggle: (IncomingRule) -> Unit,
        private val onDelete: (IncomingRule) -> Unit
    ) : RecyclerView.Adapter<IncomingRuleAdapter.Holder>() {

        private var items: List<IncomingRule> = emptyList()

        fun submit(next: List<IncomingRule>) {
            items = next
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_incoming_rule, parent, false)
            return Holder(view)
        }

        override fun onBindViewHolder(holder: Holder, position: Int) {
            holder.bind(items[position])
        }

        override fun getItemCount(): Int = items.size

        inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
            private val ivVerdict: ImageView = view.findViewById(R.id.ivRuleVerdict)
            private val tvIp: TextView = view.findViewById(R.id.tvRuleIp)
            private val tvScope: TextView = view.findViewById(R.id.tvRuleScope)
            private val btnToggle: MaterialButton = view.findViewById(R.id.btnRuleToggle)
            private val btnDelete: MaterialButton = view.findViewById(R.id.btnRuleDelete)

            fun bind(rule: IncomingRule) {
                val ctx = itemView.context
                tvIp.text = rule.normalizedIp
                val verdictLabel = ctx.getString(
                    if (rule.verdict == IncomingVerdict.ALLOW) R.string.incoming_status_allowed
                    else R.string.incoming_status_denied
                )
                tvScope.text = "$verdictLabel · ${rule.scopeLabel()}"

                val isAllow = rule.verdict == IncomingVerdict.ALLOW
                ivVerdict.setImageResource(if (isAllow) R.drawable.check_24px else R.drawable.block_24px)
                val tintAttr = if (isAllow) {
                    com.google.android.material.R.attr.colorPrimary
                } else {
                    com.google.android.material.R.attr.colorError
                }
                ivVerdict.setColorFilter(MaterialColors.getColor(ivVerdict, tintAttr))

                btnToggle.setText(if (isAllow) R.string.incoming_action_deny else R.string.incoming_action_allow)
                btnToggle.setOnClickListener { onToggle(rule) }
                btnDelete.setOnClickListener { onDelete(rule) }
            }
        }
    }
}
