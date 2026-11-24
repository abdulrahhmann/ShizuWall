package com.arslan.shizuwall.receivers

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.widget.Toast
import com.arslan.shizuwall.R
import com.arslan.shizuwall.incoming.IncomingProtocol
import com.arslan.shizuwall.incoming.IncomingRule
import com.arslan.shizuwall.incoming.IncomingRuleStore
import com.arslan.shizuwall.incoming.IncomingVerdict
import com.arslan.shizuwall.incoming.IpValidation
import com.arslan.shizuwall.services.IncomingGuardService

class IncomingActionReceiver : BroadcastReceiver() {

    companion object {
        const val ACTION_ALLOW_IP = "com.arslan.shizuwall.incoming.ACTION_ALLOW_IP"
        const val ACTION_DENY_IP = "com.arslan.shizuwall.incoming.ACTION_DENY_IP"
        const val ACTION_ALLOW_PORT = "com.arslan.shizuwall.incoming.ACTION_ALLOW_PORT"

        const val EXTRA_SOURCE_IP = "extra_source_ip"
        const val EXTRA_PROTOCOL = "extra_protocol"
        const val EXTRA_DST_PORT = "extra_dst_port"
        const val EXTRA_NOTIFICATION_ID = "extra_notification_id"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val rawIp = intent.getStringExtra(EXTRA_SOURCE_IP) ?: return
        val sourceIp = IpValidation.normalizeIp(rawIp)
        if (!IpValidation.isValidIp(sourceIp)) return

        val notificationId = intent.getIntExtra(
            EXTRA_NOTIFICATION_ID,
            IncomingGuardService.alertNotificationIdFor(sourceIp)
        )

        val rule: IncomingRule
        val toastText: String

        when (intent.action) {
            ACTION_ALLOW_IP -> {
                rule = IncomingRule(
                    sourceIp = sourceIp,
                    protocol = IncomingProtocol.ANY,
                    dstPort = null,
                    verdict = IncomingVerdict.ALLOW
                )
                toastText = context.getString(R.string.incoming_toast_allowed_ip, sourceIp)
            }
            ACTION_DENY_IP -> {
                rule = IncomingRule(
                    sourceIp = sourceIp,
                    protocol = IncomingProtocol.ANY,
                    dstPort = null,
                    verdict = IncomingVerdict.DENY
                )
                toastText = context.getString(R.string.incoming_toast_denied_ip, sourceIp)
            }
            ACTION_ALLOW_PORT -> {
                val protocol = IncomingProtocol.fromName(intent.getStringExtra(EXTRA_PROTOCOL))
                val port = intent.getIntExtra(EXTRA_DST_PORT, -1).takeIf { it in 1..65535 }
                rule = IncomingRule(
                    sourceIp = sourceIp,
                    protocol = if (protocol.supportsPort() && port != null) protocol else IncomingProtocol.ANY,
                    dstPort = if (protocol.supportsPort()) port else null,
                    verdict = IncomingVerdict.ALLOW
                )
                val allowedPort = rule.effectivePort
                toastText = if (allowedPort != null) {
                    context.getString(
                        R.string.incoming_toast_allowed_port,
                        sourceIp,
                        rule.protocol.displayName,
                        allowedPort
                    )
                } else {
                    context.getString(R.string.incoming_toast_allowed_ip, sourceIp)
                }
            }
            else -> return
        }

        IncomingRuleStore.upsertRule(context, rule)
        IncomingGuardService.reloadRules(context)

        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.cancel(notificationId)

        Toast.makeText(context, toastText, Toast.LENGTH_SHORT).show()
    }
}
